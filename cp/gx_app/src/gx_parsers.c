#include <stdint.h>
#include <stdlib.h>

#include "gx.h"

#define IS_AVP(a) (gxDict.a.avp_code == hdr->avp_code)

/*******************************************************************************/
/* private grouped avp parser function declarations                            */
/*******************************************************************************/
static int parseGxExperimentalResult(struct avp *avp, GxExperimentalResult *data);
static int parseGxPraRemove(struct avp *avp, GxPraRemove *data);
static int parseGxQosInformation(struct avp *avp, GxQosInformation *data);
static int parseGxConditionalPolicyInformation(struct avp *avp, GxConditionalPolicyInformation *data);
static int parseGxPraInstall(struct avp *avp, GxPraInstall *data);
static int parseGxAreaScope(struct avp *avp, GxAreaScope *data);
static int parseGxFlowInformation(struct avp *avp, GxFlowInformation *data);
static int parseGxTunnelInformation(struct avp *avp, GxTunnelInformation *data);
static int parseGxTftPacketFilterInformation(struct avp *avp, GxTftPacketFilterInformation *data);
static int parseGxMbsfnArea(struct avp *avp, GxMbsfnArea *data);
static int parseGxEventReportIndication(struct avp *avp, GxEventReportIndication *data);
static int parseGxTdfInformation(struct avp *avp, GxTdfInformation *data);
static int parseGxProxyInfo(struct avp *avp, GxProxyInfo *data);
static int parseGxUsedServiceUnit(struct avp *avp, GxUsedServiceUnit *data);
static int parseGxChargingRuleInstall(struct avp *avp, GxChargingRuleInstall *data);
static int parseGxChargingRuleDefinition(struct avp *avp, GxChargingRuleDefinition *data);
static int parseGxFinalUnitIndication(struct avp *avp, GxFinalUnitIndication *data);
static int parseGxUnitValue(struct avp *avp, GxUnitValue *data);
static int parseGxPresenceReportingAreaInformation(struct avp *avp, GxPresenceReportingAreaInformation *data);
static int parseGxConditionalApnAggregateMaxBitrate(struct avp *avp, GxConditionalApnAggregateMaxBitrate *data);
static int parseGxAccessNetworkChargingIdentifierGx(struct avp *avp, GxAccessNetworkChargingIdentifierGx *data);
static int parseGxOcOlr(struct avp *avp, GxOcOlr *data);
static int parseGxRoutingRuleInstall(struct avp *avp, GxRoutingRuleInstall *data);
static int parseGxTraceData(struct avp *avp, GxTraceData *data);
static int parseGxRoutingRuleDefinition(struct avp *avp, GxRoutingRuleDefinition *data);
static int parseGxMdtConfiguration(struct avp *avp, GxMdtConfiguration *data);
static int parseGxChargingRuleRemove(struct avp *avp, GxChargingRuleRemove *data);
static int parseGxAllocationRetentionPriority(struct avp *avp, GxAllocationRetentionPriority *data);
static int parseGxDefaultEpsBearerQos(struct avp *avp, GxDefaultEpsBearerQos *data);
static int parseGxRoutingRuleReport(struct avp *avp, GxRoutingRuleReport *data);
static int parseGxUserEquipmentInfo(struct avp *avp, GxUserEquipmentInfo *data);
static int parseGxSupportedFeatures(struct avp *avp, GxSupportedFeatures *data);
static int parseGxFixedUserLocationInfo(struct avp *avp, GxFixedUserLocationInfo *data);
static int parseGxDefaultQosInformation(struct avp *avp, GxDefaultQosInformation *data);
static int parseGxLoad(struct avp *avp, GxLoad *data);
static int parseGxRedirectServer(struct avp *avp, GxRedirectServer *data);
static int parseGxOcSupportedFeatures(struct avp *avp, GxOcSupportedFeatures *data);
static int parseGxPacketFilterInformation(struct avp *avp, GxPacketFilterInformation *data);
static int parseGxSubscriptionId(struct avp *avp, GxSubscriptionId *data);
static int parseGxChargingInformation(struct avp *avp, GxChargingInformation *data);
static int parseGxUsageMonitoringInformation(struct avp *avp, GxUsageMonitoringInformation *data);
static int parseGxChargingRuleReport(struct avp *avp, GxChargingRuleReport *data);
static int parseGxRedirectInformation(struct avp *avp, GxRedirectInformation *data);
static int parseGxFailedAvp(struct avp *avp, GxFailedAvp *data);
static int parseGxRoutingRuleRemove(struct avp *avp, GxRoutingRuleRemove *data);
static int parseGxRoutingFilter(struct avp *avp, GxRoutingFilter *data);
static int parseGxCoaInformation(struct avp *avp, GxCoaInformation *data);
static int parseGxGrantedServiceUnit(struct avp *avp, GxGrantedServiceUnit *data);
static int parseGxCcMoney(struct avp *avp, GxCcMoney *data);
static int parseGxApplicationDetectionInformation(struct avp *avp, GxApplicationDetectionInformation *data);
static int parseGxFlows(struct avp *avp, GxFlows *data);
static int parseGxUserCsgInformation(struct avp *avp, GxUserCsgInformation *data);

static int freeGxPraRemove(GxPraRemove *data);
static int freeGxQosInformation(GxQosInformation *data);
static int freeGxConditionalPolicyInformation(GxConditionalPolicyInformation *data);
static int freeGxPraInstall(GxPraInstall *data);
static int freeGxAreaScope(GxAreaScope *data);
static int freeGxTunnelInformation(GxTunnelInformation *data);
static int freeGxEventReportIndication(GxEventReportIndication *data);
static int freeGxUsedServiceUnit(GxUsedServiceUnit *data);
static int freeGxChargingRuleInstall(GxChargingRuleInstall *data);
static int freeGxChargingRuleDefinition(GxChargingRuleDefinition *data);
static int freeGxFinalUnitIndication(GxFinalUnitIndication *data);
static int freeGxConditionalApnAggregateMaxBitrate(GxConditionalApnAggregateMaxBitrate *data);
static int freeGxAccessNetworkChargingIdentifierGx(GxAccessNetworkChargingIdentifierGx *data);
static int freeGxRoutingRuleInstall(GxRoutingRuleInstall *data);
static int freeGxTraceData(GxTraceData *data);
static int freeGxRoutingRuleDefinition(GxRoutingRuleDefinition *data);
static int freeGxMdtConfiguration(GxMdtConfiguration *data);
static int freeGxChargingRuleRemove(GxChargingRuleRemove *data);
static int freeGxRoutingRuleReport(GxRoutingRuleReport *data);
static int freeGxUsageMonitoringInformation(GxUsageMonitoringInformation *data);
static int freeGxChargingRuleReport(GxChargingRuleReport *data);
static int freeGxRoutingRuleRemove(GxRoutingRuleRemove *data);
static int freeGxCoaInformation(GxCoaInformation *data);
static int freeGxApplicationDetectionInformation(GxApplicationDetectionInformation *data);
static int freeGxFlows(GxFlows *data);

/*******************************************************************************/
/* message parsing functions                                                   */
/*******************************************************************************/

/*
*
*       Fun:    gx_rar_parse
*
*       Desc:   Parse Re-Auth-Request Message
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Re-Auth-Request ::= <Diameter Header: 258, REQ, PXY, 16777238>
*              < Session-Id >
*              [ DRMP ]
*              { Auth-Application-Id }
*              { Origin-Host }
*              { Origin-Realm }
*              { Destination-Realm }
*              { Destination-Host }
*              { Re-Auth-Request-Type }
*              [ Session-Release-Cause ]
*              [ Origin-State-Id ]
*              [ OC-Supported-Features ]
*          *   [ Event-Trigger ]
*              [ Event-Report-Indication ]
*          *   [ Charging-Rule-Remove ]
*          *   [ Charging-Rule-Install ]
*              [ Default-EPS-Bearer-QoS ]
*          *   [ QoS-Information ]
*              [ Default-QoS-Information ]
*              [ Revalidation-Time ]
*          *   [ Usage-Monitoring-Information ]
*              [ PCSCF-Restoration-Indication ]
*          * 4 [ Conditional-Policy-Information ]
*              [ Removal-Of-Access ]
*              [ IP-CAN-Type ]
*              [ PRA-Install ]
*              [ PRA-Remove ]
*          *   [ CSG-Information-Reporting ]
*          *   [ Proxy-Info ]
*          *   [ Route-Record ]
*          *   [ AVP ]
*/
int gx_rar_parse
(
    struct msg *msg,
    GxRAR *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* clear the data buffer */
    memset((void*)data, 0, sizeof(*data));

    /* iterate through the AVPNAME child AVP's */
    FDCHECK_FCT(fd_msg_browse(msg, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_session_id)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->session_id, GX_SESSION_ID_LEN); data->presence.session_id=1; }
        else if (IS_AVP(davp_drmp)) { data->drmp = hdr->avp_value->i32; data->presence.drmp=1; }
        else if (IS_AVP(davp_auth_application_id)) { data->auth_application_id = hdr->avp_value->u32; data->presence.auth_application_id=1; }
        else if (IS_AVP(davp_origin_host)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->origin_host, GX_ORIGIN_HOST_LEN); data->presence.origin_host=1; }
        else if (IS_AVP(davp_origin_realm)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->origin_realm, GX_ORIGIN_REALM_LEN); data->presence.origin_realm=1; }
        else if (IS_AVP(davp_destination_realm)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->destination_realm, GX_DESTINATION_REALM_LEN); data->presence.destination_realm=1; }
        else if (IS_AVP(davp_destination_host)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->destination_host, GX_DESTINATION_HOST_LEN); data->presence.destination_host=1; }
        else if (IS_AVP(davp_re_auth_request_type)) { data->re_auth_request_type = hdr->avp_value->i32; data->presence.re_auth_request_type=1; }
        else if (IS_AVP(davp_session_release_cause)) { data->session_release_cause = hdr->avp_value->i32; data->presence.session_release_cause=1; }
        else if (IS_AVP(davp_origin_state_id)) { data->origin_state_id = hdr->avp_value->u32; data->presence.origin_state_id=1; }
        else if (IS_AVP(davp_oc_supported_features)) { FDCHECK_PARSE_DIRECT(parseGxOcSupportedFeatures, child_avp, &data->oc_supported_features); data->presence.oc_supported_features=1; }
        else if (IS_AVP(davp_event_trigger)) { data->event_trigger.count++; cnt++; data->presence.event_trigger=1; }
        else if (IS_AVP(davp_event_report_indication)) { FDCHECK_PARSE_DIRECT(parseGxEventReportIndication, child_avp, &data->event_report_indication); data->presence.event_report_indication=1; }
        else if (IS_AVP(davp_charging_rule_remove)) { data->charging_rule_remove.count++; cnt++; data->presence.charging_rule_remove=1; }
        else if (IS_AVP(davp_charging_rule_install)) { data->charging_rule_install.count++; cnt++; data->presence.charging_rule_install=1; }
        else if (IS_AVP(davp_default_eps_bearer_qos)) { FDCHECK_PARSE_DIRECT(parseGxDefaultEpsBearerQos, child_avp, &data->default_eps_bearer_qos); data->presence.default_eps_bearer_qos=1; }
        else if (IS_AVP(davp_qos_information)) { data->qos_information.count++; cnt++; data->presence.qos_information=1; }
        else if (IS_AVP(davp_default_qos_information)) { FDCHECK_PARSE_DIRECT(parseGxDefaultQosInformation, child_avp, &data->default_qos_information); data->presence.default_qos_information=1; }
        else if (IS_AVP(davp_revalidation_time)) { FD_PARSE_TIME(hdr->avp_value, data->revalidation_time); data->presence.revalidation_time=1; }
        else if (IS_AVP(davp_usage_monitoring_information)) { data->usage_monitoring_information.count++; cnt++; data->presence.usage_monitoring_information=1; }
        else if (IS_AVP(davp_pcscf_restoration_indication)) { data->pcscf_restoration_indication = hdr->avp_value->u32; data->presence.pcscf_restoration_indication=1; }
        else if (IS_AVP(davp_conditional_policy_information)) { data->conditional_policy_information.count++; cnt++; data->presence.conditional_policy_information=1; }
        else if (IS_AVP(davp_removal_of_access)) { data->removal_of_access = hdr->avp_value->i32; data->presence.removal_of_access=1; }
        else if (IS_AVP(davp_ip_can_type)) { data->ip_can_type = hdr->avp_value->i32; data->presence.ip_can_type=1; }
        else if (IS_AVP(davp_pra_install)) { FDCHECK_PARSE_DIRECT(parseGxPraInstall, child_avp, &data->pra_install); data->presence.pra_install=1; }
        else if (IS_AVP(davp_pra_remove)) { FDCHECK_PARSE_DIRECT(parseGxPraRemove, child_avp, &data->pra_remove); data->presence.pra_remove=1; }
        else if (IS_AVP(davp_csg_information_reporting)) { data->csg_information_reporting.count++; cnt++; data->presence.csg_information_reporting=1; }
        else if (IS_AVP(davp_proxy_info)) { data->proxy_info.count++; cnt++; data->presence.proxy_info=1; }
        else if (IS_AVP(davp_route_record)) { data->route_record.count++; cnt++; data->presence.route_record=1; }

        /* get the next child AVP */
        FDCHECK_FCT( fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->event_trigger, int32_t);
        FD_ALLOC_LIST(data->charging_rule_remove, GxChargingRuleRemove);
        FD_ALLOC_LIST(data->charging_rule_install, GxChargingRuleInstall);
        FD_ALLOC_LIST(data->qos_information, GxQosInformation);
        FD_ALLOC_LIST(data->usage_monitoring_information, GxUsageMonitoringInformation);
        FD_ALLOC_LIST(data->conditional_policy_information, GxConditionalPolicyInformation);
        FD_ALLOC_LIST(data->csg_information_reporting, int32_t);
        FD_ALLOC_LIST(data->proxy_info, GxProxyInfo);
        FD_ALLOC_LIST(data->route_record, GxRouteRecordOctetString);

        /* iterate through the AVPNAME child AVP's */
        FDCHECK_FCT(fd_msg_browse(msg, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_event_trigger)) { data->event_trigger.list[data->event_trigger.count] = hdr->avp_value->i32; data->event_trigger.count++; }
            else if (IS_AVP(davp_charging_rule_remove)) { FDCHECK_PARSE_DIRECT(parseGxChargingRuleRemove, child_avp, &data->charging_rule_remove.list[data->charging_rule_remove.count]); data->charging_rule_remove.count++; }
            else if (IS_AVP(davp_charging_rule_install)) { FDCHECK_PARSE_DIRECT(parseGxChargingRuleInstall, child_avp, &data->charging_rule_install.list[data->charging_rule_install.count]); data->charging_rule_install.count++; }
            else if (IS_AVP(davp_qos_information)) { FDCHECK_PARSE_DIRECT(parseGxQosInformation, child_avp, &data->qos_information.list[data->qos_information.count]); data->qos_information.count++; }
            else if (IS_AVP(davp_usage_monitoring_information)) { FDCHECK_PARSE_DIRECT(parseGxUsageMonitoringInformation, child_avp, &data->usage_monitoring_information.list[data->usage_monitoring_information.count]); data->usage_monitoring_information.count++; }
            else if (IS_AVP(davp_conditional_policy_information)) { FDCHECK_PARSE_DIRECT(parseGxConditionalPolicyInformation, child_avp, &data->conditional_policy_information.list[data->conditional_policy_information.count]); data->conditional_policy_information.count++; }
            else if (IS_AVP(davp_csg_information_reporting)) { data->csg_information_reporting.list[data->csg_information_reporting.count] = hdr->avp_value->i32; data->csg_information_reporting.count++; }
            else if (IS_AVP(davp_proxy_info)) { FDCHECK_PARSE_DIRECT(parseGxProxyInfo, child_avp, &data->proxy_info.list[data->proxy_info.count]); data->proxy_info.count++; }
            else if (IS_AVP(davp_route_record)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->route_record.list[data->route_record.count], GX_ROUTE_RECORD_LEN); data->route_record.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    gx_raa_parse
*
*       Desc:   Parse Re-Auth-Answer Message
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Re-Auth-Answer ::= <Diameter Header: 258, PXY, 16777238>
*              < Session-Id >
*              [ DRMP ]
*              { Origin-Host }
*              { Origin-Realm }
*              [ Result-Code ]
*              [ Experimental-Result ]
*              [ Origin-State-Id ]
*              [ OC-Supported-Features ]
*              [ OC-OLR ]
*              [ IP-CAN-Type ]
*              [ RAT-Type ]
*              [ AN-Trusted ]
*          * 2 [ AN-GW-Address ]
*              [ 3GPP-SGSN-MCC-MNC ]
*              [ 3GPP-SGSN-Address ]
*              [ 3GPP-SGSN-Ipv6-Address ]
*              [ RAI ]
*              [ 3GPP-User-Location-Info ]
*              [ User-Location-Info-Time ]
*              [ NetLoc-Access-Support ]
*              [ User-CSG-Information ]
*              [ 3GPP-MS-TimeZone ]
*              [ Default-QoS-Information ]
*          *   [ Charging-Rule-Report ]
*              [ Error-Message ]
*              [ Error-Reporting-Host ]
*              [ Failed-AVP ]
*          *   [ Proxy-Info ]
*          *   [ AVP ]
*/
int gx_raa_parse
(
    struct msg *msg,
    GxRAA *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* clear the data buffer */
    memset((void*)data, 0, sizeof(*data));

    /* iterate through the AVPNAME child AVP's */
    FDCHECK_FCT(fd_msg_browse(msg, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_session_id)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->session_id, GX_SESSION_ID_LEN); data->presence.session_id=1; }
        else if (IS_AVP(davp_drmp)) { data->drmp = hdr->avp_value->i32; data->presence.drmp=1; }
        else if (IS_AVP(davp_origin_host)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->origin_host, GX_ORIGIN_HOST_LEN); data->presence.origin_host=1; }
        else if (IS_AVP(davp_origin_realm)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->origin_realm, GX_ORIGIN_REALM_LEN); data->presence.origin_realm=1; }
        else if (IS_AVP(davp_result_code)) { data->result_code = hdr->avp_value->u32; data->presence.result_code=1; }
        else if (IS_AVP(davp_experimental_result)) { FDCHECK_PARSE_DIRECT(parseGxExperimentalResult, child_avp, &data->experimental_result); data->presence.experimental_result=1; }
        else if (IS_AVP(davp_origin_state_id)) { data->origin_state_id = hdr->avp_value->u32; data->presence.origin_state_id=1; }
        else if (IS_AVP(davp_oc_supported_features)) { FDCHECK_PARSE_DIRECT(parseGxOcSupportedFeatures, child_avp, &data->oc_supported_features); data->presence.oc_supported_features=1; }
        else if (IS_AVP(davp_oc_olr)) { FDCHECK_PARSE_DIRECT(parseGxOcOlr, child_avp, &data->oc_olr); data->presence.oc_olr=1; }
        else if (IS_AVP(davp_ip_can_type)) { data->ip_can_type = hdr->avp_value->i32; data->presence.ip_can_type=1; }
        else if (IS_AVP(davp_rat_type)) { data->rat_type = hdr->avp_value->i32; data->presence.rat_type=1; }
        else if (IS_AVP(davp_an_trusted)) { data->an_trusted = hdr->avp_value->i32; data->presence.an_trusted=1; }
        else if (IS_AVP(davp_an_gw_address)) { data->an_gw_address.count++; cnt++; data->presence.an_gw_address=1; }
        else if (IS_AVP(davp_3gpp_sgsn_mcc_mnc)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_sgsn_mcc_mnc, GX_3GPP_SGSN_MCC_MNC_LEN); data->presence.tgpp_sgsn_mcc_mnc=1; }
        else if (IS_AVP(davp_3gpp_sgsn_address)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_sgsn_address, GX_3GPP_SGSN_ADDRESS_LEN); data->presence.tgpp_sgsn_address=1; }
        else if (IS_AVP(davp_3gpp_sgsn_ipv6_address)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_sgsn_ipv6_address, GX_3GPP_SGSN_IPV6_ADDRESS_LEN); data->presence.tgpp_sgsn_ipv6_address=1; }
        else if (IS_AVP(davp_rai)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->rai, GX_RAI_LEN); data->presence.rai=1; }
        else if (IS_AVP(davp_3gpp_user_location_info)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_user_location_info, GX_3GPP_USER_LOCATION_INFO_LEN); data->presence.tgpp_user_location_info=1; }
        else if (IS_AVP(davp_user_location_info_time)) { FD_PARSE_TIME(hdr->avp_value, data->user_location_info_time); data->presence.user_location_info_time=1; }
        else if (IS_AVP(davp_netloc_access_support)) { data->netloc_access_support = hdr->avp_value->u32; data->presence.netloc_access_support=1; }
        else if (IS_AVP(davp_user_csg_information)) { FDCHECK_PARSE_DIRECT(parseGxUserCsgInformation, child_avp, &data->user_csg_information); data->presence.user_csg_information=1; }
        else if (IS_AVP(davp_3gpp_ms_timezone)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_ms_timezone, GX_3GPP_MS_TIMEZONE_LEN); data->presence.tgpp_ms_timezone=1; }
        else if (IS_AVP(davp_default_qos_information)) { FDCHECK_PARSE_DIRECT(parseGxDefaultQosInformation, child_avp, &data->default_qos_information); data->presence.default_qos_information=1; }
        else if (IS_AVP(davp_charging_rule_report)) { data->charging_rule_report.count++; cnt++; data->presence.charging_rule_report=1; }
        else if (IS_AVP(davp_error_message)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->error_message, GX_ERROR_MESSAGE_LEN); data->presence.error_message=1; }
        else if (IS_AVP(davp_error_reporting_host)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->error_reporting_host, GX_ERROR_REPORTING_HOST_LEN); data->presence.error_reporting_host=1; }
        else if (IS_AVP(davp_failed_avp)) { FDCHECK_PARSE_DIRECT(parseGxFailedAvp, child_avp, &data->failed_avp); data->presence.failed_avp=1; }
        else if (IS_AVP(davp_proxy_info)) { data->proxy_info.count++; cnt++; data->presence.proxy_info=1; }

        /* get the next child AVP */
        FDCHECK_FCT( fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->an_gw_address, FdAddress);
        FD_ALLOC_LIST(data->charging_rule_report, GxChargingRuleReport);
        FD_ALLOC_LIST(data->proxy_info, GxProxyInfo);

        /* iterate through the AVPNAME child AVP's */
        FDCHECK_FCT(fd_msg_browse(msg, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_an_gw_address)) { FD_PARSE_ADDRESS(hdr->avp_value, data->an_gw_address.list[data->an_gw_address.count]); data->an_gw_address.count++; }
            else if (IS_AVP(davp_charging_rule_report)) { FDCHECK_PARSE_DIRECT(parseGxChargingRuleReport, child_avp, &data->charging_rule_report.list[data->charging_rule_report.count]); data->charging_rule_report.count++; }
            else if (IS_AVP(davp_proxy_info)) { FDCHECK_PARSE_DIRECT(parseGxProxyInfo, child_avp, &data->proxy_info.list[data->proxy_info.count]); data->proxy_info.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    gx_cca_parse
*
*       Desc:   Parse Credit-Control-Answer Message
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Credit-Control-Answer ::= <Diameter Header: 272, PXY, 16777238>
*              < Session-Id >
*              [ DRMP ]
*              { Auth-Application-Id }
*              { Origin-Host }
*              { Origin-Realm }
*              [ Result-Code ]
*              [ Experimental-Result ]
*              { CC-Request-Type }
*              { CC-Request-Number }
*              [ OC-Supported-Features ]
*              [ OC-OLR ]
*          *   [ Supported-Features ]
*              [ Bearer-Control-Mode ]
*          *   [ Event-Trigger ]
*              [ Event-Report-Indication ]
*              [ Origin-State-Id ]
*          *   [ Redirect-Host ]
*              [ Redirect-Host-Usage ]
*              [ Redirect-Max-Cache-Time ]
*          *   [ Charging-Rule-Remove ]
*          *   [ Charging-Rule-Install ]
*              [ Charging-Information ]
*              [ Online ]
*              [ Offline ]
*          *   [ QoS-Information ]
*              [ Revalidation-Time ]
*              [ Default-EPS-Bearer-QoS ]
*              [ Default-QoS-Information ]
*              [ Bearer-Usage ]
*          *   [ Usage-Monitoring-Information ]
*          *   [ CSG-Information-Reporting ]
*              [ User-CSG-Information ]
*              [ PRA-Install ]
*              [ PRA-Remove ]
*              [ Presence-Reporting-Area-Information ]
*              [ Session-Release-Cause ]
*              [ NBIFOM-Support ]
*              [ NBIFOM-Mode ]
*              [ Default-Access ]
*              [ RAN-Rule-Support ]
*          *   [ Routing-Rule-Report ]
*          * 4 [ Conditional-Policy-Information ]
*              [ Removal-Of-Access ]
*              [ IP-CAN-Type ]
*              [ Error-Message ]
*              [ Error-Reporting-Host ]
*              [ Failed-AVP ]
*          *   [ Proxy-Info ]
*          *   [ Route-Record ]
*          *   [ Load ]
*          *   [ AVP ]
*/
int gx_cca_parse
(
    struct msg *msg,
    GxCCA *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* clear the data buffer */
    memset((void*)data, 0, sizeof(*data));

    /* iterate through the AVPNAME child AVP's */
    FDCHECK_FCT(fd_msg_browse(msg, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_session_id)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->session_id, GX_SESSION_ID_LEN); data->presence.session_id=1; }
        else if (IS_AVP(davp_drmp)) { data->drmp = hdr->avp_value->i32; data->presence.drmp=1; }
        else if (IS_AVP(davp_auth_application_id)) { data->auth_application_id = hdr->avp_value->u32; data->presence.auth_application_id=1; }
        else if (IS_AVP(davp_origin_host)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->origin_host, GX_ORIGIN_HOST_LEN); data->presence.origin_host=1; }
        else if (IS_AVP(davp_origin_realm)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->origin_realm, GX_ORIGIN_REALM_LEN); data->presence.origin_realm=1; }
        else if (IS_AVP(davp_result_code)) { data->result_code = hdr->avp_value->u32; data->presence.result_code=1; }
        else if (IS_AVP(davp_experimental_result)) { FDCHECK_PARSE_DIRECT(parseGxExperimentalResult, child_avp, &data->experimental_result); data->presence.experimental_result=1; }
        else if (IS_AVP(davp_cc_request_type)) { data->cc_request_type = hdr->avp_value->i32; data->presence.cc_request_type=1; }
        else if (IS_AVP(davp_cc_request_number)) { data->cc_request_number = hdr->avp_value->u32; data->presence.cc_request_number=1; }
        else if (IS_AVP(davp_oc_supported_features)) { FDCHECK_PARSE_DIRECT(parseGxOcSupportedFeatures, child_avp, &data->oc_supported_features); data->presence.oc_supported_features=1; }
        else if (IS_AVP(davp_oc_olr)) { FDCHECK_PARSE_DIRECT(parseGxOcOlr, child_avp, &data->oc_olr); data->presence.oc_olr=1; }
        else if (IS_AVP(davp_supported_features)) { data->supported_features.count++; cnt++; data->presence.supported_features=1; }
        else if (IS_AVP(davp_bearer_control_mode)) { data->bearer_control_mode = hdr->avp_value->i32; data->presence.bearer_control_mode=1; }
        else if (IS_AVP(davp_event_trigger)) { data->event_trigger.count++; cnt++; data->presence.event_trigger=1; }
        else if (IS_AVP(davp_event_report_indication)) { FDCHECK_PARSE_DIRECT(parseGxEventReportIndication, child_avp, &data->event_report_indication); data->presence.event_report_indication=1; }
        else if (IS_AVP(davp_origin_state_id)) { data->origin_state_id = hdr->avp_value->u32; data->presence.origin_state_id=1; }
        else if (IS_AVP(davp_redirect_host)) { data->redirect_host.count++; cnt++; data->presence.redirect_host=1; }
        else if (IS_AVP(davp_redirect_host_usage)) { data->redirect_host_usage = hdr->avp_value->i32; data->presence.redirect_host_usage=1; }
        else if (IS_AVP(davp_redirect_max_cache_time)) { data->redirect_max_cache_time = hdr->avp_value->u32; data->presence.redirect_max_cache_time=1; }
        else if (IS_AVP(davp_charging_rule_remove)) { data->charging_rule_remove.count++; cnt++; data->presence.charging_rule_remove=1; }
        else if (IS_AVP(davp_charging_rule_install)) { data->charging_rule_install.count++; cnt++; data->presence.charging_rule_install=1; }
        else if (IS_AVP(davp_charging_information)) { FDCHECK_PARSE_DIRECT(parseGxChargingInformation, child_avp, &data->charging_information); data->presence.charging_information=1; }
        else if (IS_AVP(davp_online)) { data->online = hdr->avp_value->i32; data->presence.online=1; }
        else if (IS_AVP(davp_offline)) { data->offline = hdr->avp_value->i32; data->presence.offline=1; }
        else if (IS_AVP(davp_qos_information)) { data->qos_information.count++; cnt++; data->presence.qos_information=1; }
        else if (IS_AVP(davp_revalidation_time)) { FD_PARSE_TIME(hdr->avp_value, data->revalidation_time); data->presence.revalidation_time=1; }
        else if (IS_AVP(davp_default_eps_bearer_qos)) { FDCHECK_PARSE_DIRECT(parseGxDefaultEpsBearerQos, child_avp, &data->default_eps_bearer_qos); data->presence.default_eps_bearer_qos=1; }
        else if (IS_AVP(davp_default_qos_information)) { FDCHECK_PARSE_DIRECT(parseGxDefaultQosInformation, child_avp, &data->default_qos_information); data->presence.default_qos_information=1; }
        else if (IS_AVP(davp_bearer_usage)) { data->bearer_usage = hdr->avp_value->i32; data->presence.bearer_usage=1; }
        else if (IS_AVP(davp_usage_monitoring_information)) { data->usage_monitoring_information.count++; cnt++; data->presence.usage_monitoring_information=1; }
        else if (IS_AVP(davp_csg_information_reporting)) { data->csg_information_reporting.count++; cnt++; data->presence.csg_information_reporting=1; }
        else if (IS_AVP(davp_user_csg_information)) { FDCHECK_PARSE_DIRECT(parseGxUserCsgInformation, child_avp, &data->user_csg_information); data->presence.user_csg_information=1; }
        else if (IS_AVP(davp_pra_install)) { FDCHECK_PARSE_DIRECT(parseGxPraInstall, child_avp, &data->pra_install); data->presence.pra_install=1; }
        else if (IS_AVP(davp_pra_remove)) { FDCHECK_PARSE_DIRECT(parseGxPraRemove, child_avp, &data->pra_remove); data->presence.pra_remove=1; }
        else if (IS_AVP(davp_presence_reporting_area_information)) { FDCHECK_PARSE_DIRECT(parseGxPresenceReportingAreaInformation, child_avp, &data->presence_reporting_area_information); data->presence.presence_reporting_area_information=1; }
        else if (IS_AVP(davp_session_release_cause)) { data->session_release_cause = hdr->avp_value->i32; data->presence.session_release_cause=1; }
        else if (IS_AVP(davp_nbifom_support)) { data->nbifom_support = hdr->avp_value->i32; data->presence.nbifom_support=1; }
        else if (IS_AVP(davp_nbifom_mode)) { data->nbifom_mode = hdr->avp_value->i32; data->presence.nbifom_mode=1; }
        else if (IS_AVP(davp_default_access)) { data->default_access = hdr->avp_value->i32; data->presence.default_access=1; }
        else if (IS_AVP(davp_ran_rule_support)) { data->ran_rule_support = hdr->avp_value->u32; data->presence.ran_rule_support=1; }
        else if (IS_AVP(davp_routing_rule_report)) { data->routing_rule_report.count++; cnt++; data->presence.routing_rule_report=1; }
        else if (IS_AVP(davp_conditional_policy_information)) { data->conditional_policy_information.count++; cnt++; data->presence.conditional_policy_information=1; }
        else if (IS_AVP(davp_removal_of_access)) { data->removal_of_access = hdr->avp_value->i32; data->presence.removal_of_access=1; }
        else if (IS_AVP(davp_ip_can_type)) { data->ip_can_type = hdr->avp_value->i32; data->presence.ip_can_type=1; }
        else if (IS_AVP(davp_error_message)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->error_message, GX_ERROR_MESSAGE_LEN); data->presence.error_message=1; }
        else if (IS_AVP(davp_error_reporting_host)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->error_reporting_host, GX_ERROR_REPORTING_HOST_LEN); data->presence.error_reporting_host=1; }
        else if (IS_AVP(davp_failed_avp)) { FDCHECK_PARSE_DIRECT(parseGxFailedAvp, child_avp, &data->failed_avp); data->presence.failed_avp=1; }
        else if (IS_AVP(davp_proxy_info)) { data->proxy_info.count++; cnt++; data->presence.proxy_info=1; }
        else if (IS_AVP(davp_route_record)) { data->route_record.count++; cnt++; data->presence.route_record=1; }
        else if (IS_AVP(davp_load)) { data->load.count++; cnt++; data->presence.load=1; }

        /* get the next child AVP */
        FDCHECK_FCT( fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->supported_features, GxSupportedFeatures);
        FD_ALLOC_LIST(data->event_trigger, int32_t);
        FD_ALLOC_LIST(data->redirect_host, GxRedirectHostOctetString);
        FD_ALLOC_LIST(data->charging_rule_remove, GxChargingRuleRemove);
        FD_ALLOC_LIST(data->charging_rule_install, GxChargingRuleInstall);
        FD_ALLOC_LIST(data->qos_information, GxQosInformation);
        FD_ALLOC_LIST(data->usage_monitoring_information, GxUsageMonitoringInformation);
        FD_ALLOC_LIST(data->csg_information_reporting, int32_t);
        FD_ALLOC_LIST(data->routing_rule_report, GxRoutingRuleReport);
        FD_ALLOC_LIST(data->conditional_policy_information, GxConditionalPolicyInformation);
        FD_ALLOC_LIST(data->proxy_info, GxProxyInfo);
        FD_ALLOC_LIST(data->route_record, GxRouteRecordOctetString);
        FD_ALLOC_LIST(data->load, GxLoad);

        /* iterate through the AVPNAME child AVP's */
        FDCHECK_FCT(fd_msg_browse(msg, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_supported_features)) { FDCHECK_PARSE_DIRECT(parseGxSupportedFeatures, child_avp, &data->supported_features.list[data->supported_features.count]); data->supported_features.count++; }
            else if (IS_AVP(davp_event_trigger)) { data->event_trigger.list[data->event_trigger.count] = hdr->avp_value->i32; data->event_trigger.count++; }
            else if (IS_AVP(davp_redirect_host)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->redirect_host.list[data->redirect_host.count], GX_REDIRECT_HOST_LEN); data->redirect_host.count++; }
            else if (IS_AVP(davp_charging_rule_remove)) { FDCHECK_PARSE_DIRECT(parseGxChargingRuleRemove, child_avp, &data->charging_rule_remove.list[data->charging_rule_remove.count]); data->charging_rule_remove.count++; }
            else if (IS_AVP(davp_charging_rule_install)) { FDCHECK_PARSE_DIRECT(parseGxChargingRuleInstall, child_avp, &data->charging_rule_install.list[data->charging_rule_install.count]); data->charging_rule_install.count++; }
            else if (IS_AVP(davp_qos_information)) { FDCHECK_PARSE_DIRECT(parseGxQosInformation, child_avp, &data->qos_information.list[data->qos_information.count]); data->qos_information.count++; }
            else if (IS_AVP(davp_usage_monitoring_information)) { FDCHECK_PARSE_DIRECT(parseGxUsageMonitoringInformation, child_avp, &data->usage_monitoring_information.list[data->usage_monitoring_information.count]); data->usage_monitoring_information.count++; }
            else if (IS_AVP(davp_csg_information_reporting)) { data->csg_information_reporting.list[data->csg_information_reporting.count] = hdr->avp_value->i32; data->csg_information_reporting.count++; }
            else if (IS_AVP(davp_routing_rule_report)) { FDCHECK_PARSE_DIRECT(parseGxRoutingRuleReport, child_avp, &data->routing_rule_report.list[data->routing_rule_report.count]); data->routing_rule_report.count++; }
            else if (IS_AVP(davp_conditional_policy_information)) { FDCHECK_PARSE_DIRECT(parseGxConditionalPolicyInformation, child_avp, &data->conditional_policy_information.list[data->conditional_policy_information.count]); data->conditional_policy_information.count++; }
            else if (IS_AVP(davp_proxy_info)) { FDCHECK_PARSE_DIRECT(parseGxProxyInfo, child_avp, &data->proxy_info.list[data->proxy_info.count]); data->proxy_info.count++; }
            else if (IS_AVP(davp_route_record)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->route_record.list[data->route_record.count], GX_ROUTE_RECORD_LEN); data->route_record.count++; }
            else if (IS_AVP(davp_load)) { FDCHECK_PARSE_DIRECT(parseGxLoad, child_avp, &data->load.list[data->load.count]); data->load.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    gx_ccr_parse
*
*       Desc:   Parse Credit-Control-Request Message
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Credit-Control-Request ::= <Diameter Header: 272, REQ, PXY, 16777238>
*              < Session-Id >
*              [ DRMP ]
*              { Auth-Application-Id }
*              { Origin-Host }
*              { Origin-Realm }
*              { Destination-Realm }
*              { CC-Request-Type }
*              { CC-Request-Number }
*              [ Credit-Management-Status ]
*              [ Destination-Host ]
*              [ Origin-State-Id ]
*          *   [ Subscription-Id ]
*              [ OC-Supported-Features ]
*          *   [ Supported-Features ]
*              [ TDF-Information ]
*              [ Network-Request-Support ]
*          *   [ Packet-Filter-Information ]
*              [ Packet-Filter-Operation ]
*              [ Bearer-Identifier ]
*              [ Bearer-Operation ]
*              [ Dynamic-Address-Flag ]
*              [ Dynamic-Address-Flag-Extension ]
*              [ PDN-Connection-Charging-ID ]
*              [ Framed-IP-Address ]
*              [ Framed-IPv6-Prefix ]
*              [ IP-CAN-Type ]
*              [ 3GPP-RAT-Type ]
*              [ AN-Trusted ]
*              [ RAT-Type ]
*              [ Termination-Cause ]
*              [ User-Equipment-Info ]
*              [ QoS-Information ]
*              [ QoS-Negotiation ]
*              [ QoS-Upgrade ]
*              [ Default-EPS-Bearer-QoS ]
*              [ Default-QoS-Information ]
*          * 2 [ AN-GW-Address ]
*              [ AN-GW-Status ]
*              [ 3GPP-SGSN-MCC-MNC ]
*              [ 3GPP-SGSN-Address ]
*              [ 3GPP-SGSN-Ipv6-Address ]
*              [ 3GPP-GGSN-Address ]
*              [ 3GPP-GGSN-Ipv6-Address ]
*              [ 3GPP-Selection-Mode ]
*              [ RAI ]
*              [ 3GPP-User-Location-Info ]
*              [ Fixed-User-Location-Info ]
*              [ User-Location-Info-Time ]
*              [ User-CSG-Information ]
*              [ TWAN-Identifier ]
*              [ 3GPP-MS-TimeZone ]
*          *   [ RAN-NAS-Release-Cause ]
*              [ 3GPP-Charging-Characteristics ]
*              [ Called-Station-Id ]
*              [ PDN-Connection-ID ]
*              [ Bearer-Usage ]
*              [ Online ]
*              [ Offline ]
*          *   [ TFT-Packet-Filter-Information ]
*          *   [ Charging-Rule-Report ]
*          *   [ Application-Detection-Information ]
*          *   [ Event-Trigger ]
*              [ Event-Report-Indication ]
*              [ Access-Network-Charging-Address ]
*          *   [ Access-Network-Charging-Identifier-Gx ]
*          *   [ CoA-Information ]
*          *   [ Usage-Monitoring-Information ]
*              [ NBIFOM-Support ]
*              [ NBIFOM-Mode ]
*              [ Default-Access ]
*              [ Origination-Time-Stamp ]
*              [ Maximum-Wait-Time ]
*              [ Access-Availability-Change-Reason ]
*              [ Routing-Rule-Install ]
*              [ Routing-Rule-Remove ]
*              [ HeNB-Local-IP-Address ]
*              [ UE-Local-IP-Address ]
*              [ UDP-Source-Port ]
*              [ TCP-Source-Port ]
*          *   [ Presence-Reporting-Area-Information ]
*              [ Logical-Access-Id ]
*              [ Physical-Access-Id ]
*          *   [ Proxy-Info ]
*          *   [ Route-Record ]
*              [ 3GPP-PS-Data-Off-Status ]
*          *   [ AVP ]
*/
int gx_ccr_parse
(
    struct msg *msg,
    GxCCR *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* clear the data buffer */
    memset((void*)data, 0, sizeof(*data));

    /* iterate through the AVPNAME child AVP's */
    FDCHECK_FCT(fd_msg_browse(msg, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_session_id)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->session_id, GX_SESSION_ID_LEN); data->presence.session_id=1; }
        else if (IS_AVP(davp_drmp)) { data->drmp = hdr->avp_value->i32; data->presence.drmp=1; }
        else if (IS_AVP(davp_auth_application_id)) { data->auth_application_id = hdr->avp_value->u32; data->presence.auth_application_id=1; }
        else if (IS_AVP(davp_origin_host)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->origin_host, GX_ORIGIN_HOST_LEN); data->presence.origin_host=1; }
        else if (IS_AVP(davp_origin_realm)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->origin_realm, GX_ORIGIN_REALM_LEN); data->presence.origin_realm=1; }
        else if (IS_AVP(davp_destination_realm)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->destination_realm, GX_DESTINATION_REALM_LEN); data->presence.destination_realm=1; }
        else if (IS_AVP(davp_service_context_id)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->service_context_id, GX_SERVICE_CONTEXT_ID_LEN); data->presence.service_context_id=1; }
        else if (IS_AVP(davp_cc_request_type)) { data->cc_request_type = hdr->avp_value->i32; data->presence.cc_request_type=1; }
        else if (IS_AVP(davp_cc_request_type)) { data->cc_request_type = hdr->avp_value->i32; data->presence.cc_request_type=1; }
        else if (IS_AVP(davp_cc_request_number)) { data->cc_request_number = hdr->avp_value->u32; data->presence.cc_request_number=1; }
        else if (IS_AVP(davp_credit_management_status)) { data->credit_management_status = hdr->avp_value->u32; data->presence.credit_management_status=1; }
        else if (IS_AVP(davp_destination_host)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->destination_host, GX_DESTINATION_HOST_LEN); data->presence.destination_host=1; }
        else if (IS_AVP(davp_origin_state_id)) { data->origin_state_id = hdr->avp_value->u32; data->presence.origin_state_id=1; }
        else if (IS_AVP(davp_subscription_id)) { data->subscription_id.count++; cnt++; data->presence.subscription_id=1; }
        else if (IS_AVP(davp_oc_supported_features)) { FDCHECK_PARSE_DIRECT(parseGxOcSupportedFeatures, child_avp, &data->oc_supported_features); data->presence.oc_supported_features=1; }
        else if (IS_AVP(davp_supported_features)) { data->supported_features.count++; cnt++; data->presence.supported_features=1; }
        else if (IS_AVP(davp_tdf_information)) { FDCHECK_PARSE_DIRECT(parseGxTdfInformation, child_avp, &data->tdf_information); data->presence.tdf_information=1; }
        else if (IS_AVP(davp_network_request_support)) { data->network_request_support = hdr->avp_value->i32; data->presence.network_request_support=1; }
        else if (IS_AVP(davp_packet_filter_information)) { data->packet_filter_information.count++; cnt++; data->presence.packet_filter_information=1; }
        else if (IS_AVP(davp_packet_filter_operation)) { data->packet_filter_operation = hdr->avp_value->i32; data->presence.packet_filter_operation=1; }
        else if (IS_AVP(davp_bearer_identifier)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->bearer_identifier, GX_BEARER_IDENTIFIER_LEN); data->presence.bearer_identifier=1; }
        else if (IS_AVP(davp_bearer_operation)) { data->bearer_operation = hdr->avp_value->i32; data->presence.bearer_operation=1; }
        else if (IS_AVP(davp_dynamic_address_flag)) { data->dynamic_address_flag = hdr->avp_value->i32; data->presence.dynamic_address_flag=1; }
        else if (IS_AVP(davp_dynamic_address_flag_extension)) { data->dynamic_address_flag_extension = hdr->avp_value->i32; data->presence.dynamic_address_flag_extension=1; }
        else if (IS_AVP(davp_pdn_connection_charging_id)) { data->pdn_connection_charging_id = hdr->avp_value->u32; data->presence.pdn_connection_charging_id=1; }
        else if (IS_AVP(davp_framed_ip_address)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->framed_ip_address, GX_FRAMED_IP_ADDRESS_LEN); data->presence.framed_ip_address=1; }
        else if (IS_AVP(davp_framed_ipv6_prefix)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->framed_ipv6_prefix, GX_FRAMED_IPV6_PREFIX_LEN); data->presence.framed_ipv6_prefix=1; }
        else if (IS_AVP(davp_ip_can_type)) { data->ip_can_type = hdr->avp_value->i32; data->presence.ip_can_type=1; }
        else if (IS_AVP(davp_3gpp_rat_type)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_rat_type, GX_3GPP_RAT_TYPE_LEN); data->presence.tgpp_rat_type=1; }
        else if (IS_AVP(davp_an_trusted)) { data->an_trusted = hdr->avp_value->i32; data->presence.an_trusted=1; }
        else if (IS_AVP(davp_rat_type)) { data->rat_type = hdr->avp_value->i32; data->presence.rat_type=1; }
        else if (IS_AVP(davp_termination_cause)) { data->termination_cause = hdr->avp_value->i32; data->presence.termination_cause=1; }
        else if (IS_AVP(davp_user_equipment_info)) { FDCHECK_PARSE_DIRECT(parseGxUserEquipmentInfo, child_avp, &data->user_equipment_info); data->presence.user_equipment_info=1; }
        else if (IS_AVP(davp_qos_information)) { FDCHECK_PARSE_DIRECT(parseGxQosInformation, child_avp, &data->qos_information); data->presence.qos_information=1; }
        else if (IS_AVP(davp_qos_negotiation)) { data->qos_negotiation = hdr->avp_value->i32; data->presence.qos_negotiation=1; }
        else if (IS_AVP(davp_qos_upgrade)) { data->qos_upgrade = hdr->avp_value->i32; data->presence.qos_upgrade=1; }
        else if (IS_AVP(davp_default_eps_bearer_qos)) { FDCHECK_PARSE_DIRECT(parseGxDefaultEpsBearerQos, child_avp, &data->default_eps_bearer_qos); data->presence.default_eps_bearer_qos=1; }
        else if (IS_AVP(davp_default_qos_information)) { FDCHECK_PARSE_DIRECT(parseGxDefaultQosInformation, child_avp, &data->default_qos_information); data->presence.default_qos_information=1; }
        else if (IS_AVP(davp_an_gw_address)) { data->an_gw_address.count++; cnt++; data->presence.an_gw_address=1; }
        else if (IS_AVP(davp_an_gw_status)) { data->an_gw_status = hdr->avp_value->i32; data->presence.an_gw_status=1; }
        else if (IS_AVP(davp_3gpp_sgsn_mcc_mnc)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_sgsn_mcc_mnc, GX_3GPP_SGSN_MCC_MNC_LEN); data->presence.tgpp_sgsn_mcc_mnc=1; }
        else if (IS_AVP(davp_3gpp_sgsn_address)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_sgsn_address, GX_3GPP_SGSN_ADDRESS_LEN); data->presence.tgpp_sgsn_address=1; }
        else if (IS_AVP(davp_3gpp_sgsn_ipv6_address)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_sgsn_ipv6_address, GX_3GPP_SGSN_IPV6_ADDRESS_LEN); data->presence.tgpp_sgsn_ipv6_address=1; }
        else if (IS_AVP(davp_3gpp_ggsn_address)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_ggsn_address, GX_3GPP_GGSN_ADDRESS_LEN); data->presence.tgpp_ggsn_address=1; }
        else if (IS_AVP(davp_3gpp_ggsn_ipv6_address)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_ggsn_ipv6_address, GX_3GPP_GGSN_IPV6_ADDRESS_LEN); data->presence.tgpp_ggsn_ipv6_address=1; }
        else if (IS_AVP(davp_3gpp_selection_mode)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_selection_mode, GX_3GPP_SELECTION_MODE_LEN); data->presence.tgpp_selection_mode=1; }
        else if (IS_AVP(davp_rai)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->rai, GX_RAI_LEN); data->presence.rai=1; }
        else if (IS_AVP(davp_3gpp_user_location_info)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_user_location_info, GX_3GPP_USER_LOCATION_INFO_LEN); data->presence.tgpp_user_location_info=1; }
        else if (IS_AVP(davp_fixed_user_location_info)) { FDCHECK_PARSE_DIRECT(parseGxFixedUserLocationInfo, child_avp, &data->fixed_user_location_info); data->presence.fixed_user_location_info=1; }
        else if (IS_AVP(davp_user_location_info_time)) { FD_PARSE_TIME(hdr->avp_value, data->user_location_info_time); data->presence.user_location_info_time=1; }
        else if (IS_AVP(davp_user_csg_information)) { FDCHECK_PARSE_DIRECT(parseGxUserCsgInformation, child_avp, &data->user_csg_information); data->presence.user_csg_information=1; }
        else if (IS_AVP(davp_twan_identifier)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->twan_identifier, GX_TWAN_IDENTIFIER_LEN); data->presence.twan_identifier=1; }
        else if (IS_AVP(davp_3gpp_ms_timezone)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_ms_timezone, GX_3GPP_MS_TIMEZONE_LEN); data->presence.tgpp_ms_timezone=1; }
        else if (IS_AVP(davp_ran_nas_release_cause)) { data->ran_nas_release_cause.count++; cnt++; data->presence.ran_nas_release_cause=1; }
        else if (IS_AVP(davp_3gpp_charging_characteristics)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_charging_characteristics, GX_3GPP_CHARGING_CHARACTERISTICS_LEN); data->presence.tgpp_charging_characteristics=1; }
        else if (IS_AVP(davp_called_station_id)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->called_station_id, GX_CALLED_STATION_ID_LEN); data->presence.called_station_id=1; }
        else if (IS_AVP(davp_pdn_connection_id)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->pdn_connection_id, GX_PDN_CONNECTION_ID_LEN); data->presence.pdn_connection_id=1; }
        else if (IS_AVP(davp_bearer_usage)) { data->bearer_usage = hdr->avp_value->i32; data->presence.bearer_usage=1; }
        else if (IS_AVP(davp_online)) { data->online = hdr->avp_value->i32; data->presence.online=1; }
        else if (IS_AVP(davp_offline)) { data->offline = hdr->avp_value->i32; data->presence.offline=1; }
        else if (IS_AVP(davp_tft_packet_filter_information)) { data->tft_packet_filter_information.count++; cnt++; data->presence.tft_packet_filter_information=1; }
        else if (IS_AVP(davp_charging_rule_report)) { data->charging_rule_report.count++; cnt++; data->presence.charging_rule_report=1; }
        else if (IS_AVP(davp_application_detection_information)) { data->application_detection_information.count++; cnt++; data->presence.application_detection_information=1; }
        else if (IS_AVP(davp_event_trigger)) { data->event_trigger.count++; cnt++; data->presence.event_trigger=1; }
        else if (IS_AVP(davp_event_report_indication)) { FDCHECK_PARSE_DIRECT(parseGxEventReportIndication, child_avp, &data->event_report_indication); data->presence.event_report_indication=1; }
        else if (IS_AVP(davp_access_network_charging_address)) { FD_PARSE_ADDRESS(hdr->avp_value, data->access_network_charging_address); data->presence.access_network_charging_address=1; }
        else if (IS_AVP(davp_access_network_charging_identifier_gx)) { data->access_network_charging_identifier_gx.count++; cnt++; data->presence.access_network_charging_identifier_gx=1; }
        else if (IS_AVP(davp_coa_information)) { data->coa_information.count++; cnt++; data->presence.coa_information=1; }
        else if (IS_AVP(davp_usage_monitoring_information)) { data->usage_monitoring_information.count++; cnt++; data->presence.usage_monitoring_information=1; }
        else if (IS_AVP(davp_nbifom_support)) { data->nbifom_support = hdr->avp_value->i32; data->presence.nbifom_support=1; }
        else if (IS_AVP(davp_nbifom_mode)) { data->nbifom_mode = hdr->avp_value->i32; data->presence.nbifom_mode=1; }
        else if (IS_AVP(davp_default_access)) { data->default_access = hdr->avp_value->i32; data->presence.default_access=1; }
        else if (IS_AVP(davp_origination_time_stamp)) { data->origination_time_stamp = hdr->avp_value->u64; data->presence.origination_time_stamp=1; }
        else if (IS_AVP(davp_maximum_wait_time)) { data->maximum_wait_time = hdr->avp_value->u32; data->presence.maximum_wait_time=1; }
        else if (IS_AVP(davp_access_availability_change_reason)) { data->access_availability_change_reason = hdr->avp_value->u32; data->presence.access_availability_change_reason=1; }
        else if (IS_AVP(davp_routing_rule_install)) { FDCHECK_PARSE_DIRECT(parseGxRoutingRuleInstall, child_avp, &data->routing_rule_install); data->presence.routing_rule_install=1; }
        else if (IS_AVP(davp_routing_rule_remove)) { FDCHECK_PARSE_DIRECT(parseGxRoutingRuleRemove, child_avp, &data->routing_rule_remove); data->presence.routing_rule_remove=1; }
        else if (IS_AVP(davp_henb_local_ip_address)) { FD_PARSE_ADDRESS(hdr->avp_value, data->henb_local_ip_address); data->presence.henb_local_ip_address=1; }
        else if (IS_AVP(davp_ue_local_ip_address)) { FD_PARSE_ADDRESS(hdr->avp_value, data->ue_local_ip_address); data->presence.ue_local_ip_address=1; }
        else if (IS_AVP(davp_udp_source_port)) { data->udp_source_port = hdr->avp_value->u32; data->presence.udp_source_port=1; }
        else if (IS_AVP(davp_tcp_source_port)) { data->tcp_source_port = hdr->avp_value->u32; data->presence.tcp_source_port=1; }
        else if (IS_AVP(davp_presence_reporting_area_information)) { data->presence_reporting_area_information.count++; cnt++; data->presence.presence_reporting_area_information=1; }
        else if (IS_AVP(davp_logical_access_id)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->logical_access_id, GX_LOGICAL_ACCESS_ID_LEN); data->presence.logical_access_id=1; }
        else if (IS_AVP(davp_physical_access_id)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->physical_access_id, GX_PHYSICAL_ACCESS_ID_LEN); data->presence.physical_access_id=1; }
        else if (IS_AVP(davp_proxy_info)) { data->proxy_info.count++; cnt++; data->presence.proxy_info=1; }
        else if (IS_AVP(davp_route_record)) { data->route_record.count++; cnt++; data->presence.route_record=1; }
        else if (IS_AVP(davp_3gpp_ps_data_off_status)) { data->tgpp_ps_data_off_status = hdr->avp_value->i32; data->presence.tgpp_ps_data_off_status=1; }

        /* get the next child AVP */
        FDCHECK_FCT( fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->subscription_id, GxSubscriptionId);
        FD_ALLOC_LIST(data->supported_features, GxSupportedFeatures);
        FD_ALLOC_LIST(data->packet_filter_information, GxPacketFilterInformation);
        FD_ALLOC_LIST(data->an_gw_address, FdAddress);
        FD_ALLOC_LIST(data->ran_nas_release_cause, GxRanNasReleaseCauseOctetString);
        FD_ALLOC_LIST(data->tft_packet_filter_information, GxTftPacketFilterInformation);
        FD_ALLOC_LIST(data->charging_rule_report, GxChargingRuleReport);
        FD_ALLOC_LIST(data->application_detection_information, GxApplicationDetectionInformation);
        FD_ALLOC_LIST(data->event_trigger, int32_t);
        FD_ALLOC_LIST(data->access_network_charging_identifier_gx, GxAccessNetworkChargingIdentifierGx);
        FD_ALLOC_LIST(data->coa_information, GxCoaInformation);
        FD_ALLOC_LIST(data->usage_monitoring_information, GxUsageMonitoringInformation);
        FD_ALLOC_LIST(data->presence_reporting_area_information, GxPresenceReportingAreaInformation);
        FD_ALLOC_LIST(data->proxy_info, GxProxyInfo);
        FD_ALLOC_LIST(data->route_record, GxRouteRecordOctetString);

        /* iterate through the AVPNAME child AVP's */
        FDCHECK_FCT(fd_msg_browse(msg, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_subscription_id)) { FDCHECK_PARSE_DIRECT(parseGxSubscriptionId, child_avp, &data->subscription_id.list[data->subscription_id.count]); data->subscription_id.count++; }
            else if (IS_AVP(davp_supported_features)) { FDCHECK_PARSE_DIRECT(parseGxSupportedFeatures, child_avp, &data->supported_features.list[data->supported_features.count]); data->supported_features.count++; }
            else if (IS_AVP(davp_packet_filter_information)) { FDCHECK_PARSE_DIRECT(parseGxPacketFilterInformation, child_avp, &data->packet_filter_information.list[data->packet_filter_information.count]); data->packet_filter_information.count++; }
            else if (IS_AVP(davp_an_gw_address)) { FD_PARSE_ADDRESS(hdr->avp_value, data->an_gw_address.list[data->an_gw_address.count]); data->an_gw_address.count++; }
            else if (IS_AVP(davp_ran_nas_release_cause)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->ran_nas_release_cause.list[data->ran_nas_release_cause.count], GX_RAN_NAS_RELEASE_CAUSE_LEN); data->ran_nas_release_cause.count++; }
            else if (IS_AVP(davp_tft_packet_filter_information)) { FDCHECK_PARSE_DIRECT(parseGxTftPacketFilterInformation, child_avp, &data->tft_packet_filter_information.list[data->tft_packet_filter_information.count]); data->tft_packet_filter_information.count++; }
            else if (IS_AVP(davp_charging_rule_report)) { FDCHECK_PARSE_DIRECT(parseGxChargingRuleReport, child_avp, &data->charging_rule_report.list[data->charging_rule_report.count]); data->charging_rule_report.count++; }
            else if (IS_AVP(davp_application_detection_information)) { FDCHECK_PARSE_DIRECT(parseGxApplicationDetectionInformation, child_avp, &data->application_detection_information.list[data->application_detection_information.count]); data->application_detection_information.count++; }
            else if (IS_AVP(davp_event_trigger)) { data->event_trigger.list[data->event_trigger.count] = hdr->avp_value->i32; data->event_trigger.count++; }
            else if (IS_AVP(davp_access_network_charging_identifier_gx)) { FDCHECK_PARSE_DIRECT(parseGxAccessNetworkChargingIdentifierGx, child_avp, &data->access_network_charging_identifier_gx.list[data->access_network_charging_identifier_gx.count]); data->access_network_charging_identifier_gx.count++; }
            else if (IS_AVP(davp_coa_information)) { FDCHECK_PARSE_DIRECT(parseGxCoaInformation, child_avp, &data->coa_information.list[data->coa_information.count]); data->coa_information.count++; }
            else if (IS_AVP(davp_usage_monitoring_information)) { FDCHECK_PARSE_DIRECT(parseGxUsageMonitoringInformation, child_avp, &data->usage_monitoring_information.list[data->usage_monitoring_information.count]); data->usage_monitoring_information.count++; }
            else if (IS_AVP(davp_presence_reporting_area_information)) { FDCHECK_PARSE_DIRECT(parseGxPresenceReportingAreaInformation, child_avp, &data->presence_reporting_area_information.list[data->presence_reporting_area_information.count]); data->presence_reporting_area_information.count++; }
            else if (IS_AVP(davp_proxy_info)) { FDCHECK_PARSE_DIRECT(parseGxProxyInfo, child_avp, &data->proxy_info.list[data->proxy_info.count]); data->proxy_info.count++; }
            else if (IS_AVP(davp_route_record)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->route_record.list[data->route_record.count], GX_ROUTE_RECORD_LEN); data->route_record.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*******************************************************************************/
/* free message data functions                                                 */
/*******************************************************************************/

/*
*
*       Fun:    gx_rar_free
*
*       Desc:   Free the multiple occurrance AVP's for Re-Auth-Request
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Re-Auth-Request ::= <Diameter Header: 258, REQ, PXY, 16777238>
*              < Session-Id >
*              [ DRMP ]
*              { Auth-Application-Id }
*              { Origin-Host }
*              { Origin-Realm }
*              { Destination-Realm }
*              { Destination-Host }
*              { Re-Auth-Request-Type }
*              [ Session-Release-Cause ]
*              [ Origin-State-Id ]
*              [ OC-Supported-Features ]
*          *   [ Event-Trigger ]
*              [ Event-Report-Indication ]
*          *   [ Charging-Rule-Remove ]
*          *   [ Charging-Rule-Install ]
*              [ Default-EPS-Bearer-QoS ]
*          *   [ QoS-Information ]
*              [ Default-QoS-Information ]
*              [ Revalidation-Time ]
*          *   [ Usage-Monitoring-Information ]
*              [ PCSCF-Restoration-Indication ]
*          * 4 [ Conditional-Policy-Information ]
*              [ Removal-Of-Access ]
*              [ IP-CAN-Type ]
*              [ PRA-Install ]
*              [ PRA-Remove ]
*          *   [ CSG-Information-Reporting ]
*          *   [ Proxy-Info ]
*          *   [ Route-Record ]
*          *   [ AVP ]
*/
int gx_rar_free
(
    GxRAR *data
)
{
    FD_CALLFREE_STRUCT( data->event_report_indication, freeGxEventReportIndication );
    FD_CALLFREE_LIST( data->charging_rule_remove, freeGxChargingRuleRemove );
    FD_CALLFREE_LIST( data->charging_rule_install, freeGxChargingRuleInstall );
    FD_CALLFREE_LIST( data->qos_information, freeGxQosInformation );
    FD_CALLFREE_LIST( data->usage_monitoring_information, freeGxUsageMonitoringInformation );
    FD_CALLFREE_LIST( data->conditional_policy_information, freeGxConditionalPolicyInformation );
    FD_CALLFREE_STRUCT( data->pra_install, freeGxPraInstall );
    FD_CALLFREE_STRUCT( data->pra_remove, freeGxPraRemove );

    FD_FREE_LIST( data->event_trigger );
    FD_FREE_LIST( data->charging_rule_remove );
    FD_FREE_LIST( data->charging_rule_install );
    FD_FREE_LIST( data->qos_information );
    FD_FREE_LIST( data->usage_monitoring_information );
    FD_FREE_LIST( data->conditional_policy_information );
    FD_FREE_LIST( data->csg_information_reporting );
    FD_FREE_LIST( data->proxy_info );
    FD_FREE_LIST( data->route_record );

    return FD_REASON_OK;
}

/*
*
*       Fun:    gx_raa_free
*
*       Desc:   Free the multiple occurrance AVP's for Re-Auth-Answer
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Re-Auth-Answer ::= <Diameter Header: 258, PXY, 16777238>
*              < Session-Id >
*              [ DRMP ]
*              { Origin-Host }
*              { Origin-Realm }
*              [ Result-Code ]
*              [ Experimental-Result ]
*              [ Origin-State-Id ]
*              [ OC-Supported-Features ]
*              [ OC-OLR ]
*              [ IP-CAN-Type ]
*              [ RAT-Type ]
*              [ AN-Trusted ]
*          * 2 [ AN-GW-Address ]
*              [ 3GPP-SGSN-MCC-MNC ]
*              [ 3GPP-SGSN-Address ]
*              [ 3GPP-SGSN-Ipv6-Address ]
*              [ RAI ]
*              [ 3GPP-User-Location-Info ]
*              [ User-Location-Info-Time ]
*              [ NetLoc-Access-Support ]
*              [ User-CSG-Information ]
*              [ 3GPP-MS-TimeZone ]
*              [ Default-QoS-Information ]
*          *   [ Charging-Rule-Report ]
*              [ Error-Message ]
*              [ Error-Reporting-Host ]
*              [ Failed-AVP ]
*          *   [ Proxy-Info ]
*          *   [ AVP ]
*/
int gx_raa_free
(
    GxRAA *data
)
{
    FD_CALLFREE_LIST( data->charging_rule_report, freeGxChargingRuleReport );

    FD_FREE_LIST( data->an_gw_address );
    FD_FREE_LIST( data->charging_rule_report );
    FD_FREE_LIST( data->proxy_info );

    return FD_REASON_OK;
}

/*
*
*       Fun:    gx_cca_free
*
*       Desc:   Free the multiple occurrance AVP's for Credit-Control-Answer
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Credit-Control-Answer ::= <Diameter Header: 272, PXY, 16777238>
*              < Session-Id >
*              [ DRMP ]
*              { Auth-Application-Id }
*              { Origin-Host }
*              { Origin-Realm }
*              [ Result-Code ]
*              [ Experimental-Result ]
*              { CC-Request-Type }
*              { CC-Request-Number }
*              [ OC-Supported-Features ]
*              [ OC-OLR ]
*          *   [ Supported-Features ]
*              [ Bearer-Control-Mode ]
*          *   [ Event-Trigger ]
*              [ Event-Report-Indication ]
*              [ Origin-State-Id ]
*          *   [ Redirect-Host ]
*              [ Redirect-Host-Usage ]
*              [ Redirect-Max-Cache-Time ]
*          *   [ Charging-Rule-Remove ]
*          *   [ Charging-Rule-Install ]
*              [ Charging-Information ]
*              [ Online ]
*              [ Offline ]
*          *   [ QoS-Information ]
*              [ Revalidation-Time ]
*              [ Default-EPS-Bearer-QoS ]
*              [ Default-QoS-Information ]
*              [ Bearer-Usage ]
*          *   [ Usage-Monitoring-Information ]
*          *   [ CSG-Information-Reporting ]
*              [ User-CSG-Information ]
*              [ PRA-Install ]
*              [ PRA-Remove ]
*              [ Presence-Reporting-Area-Information ]
*              [ Session-Release-Cause ]
*              [ NBIFOM-Support ]
*              [ NBIFOM-Mode ]
*              [ Default-Access ]
*              [ RAN-Rule-Support ]
*          *   [ Routing-Rule-Report ]
*          * 4 [ Conditional-Policy-Information ]
*              [ Removal-Of-Access ]
*              [ IP-CAN-Type ]
*              [ Error-Message ]
*              [ Error-Reporting-Host ]
*              [ Failed-AVP ]
*          *   [ Proxy-Info ]
*          *   [ Route-Record ]
*          *   [ Load ]
*          *   [ AVP ]
*/
int gx_cca_free
(
    GxCCA *data
)
{
    FD_CALLFREE_STRUCT( data->event_report_indication, freeGxEventReportIndication );
    FD_CALLFREE_LIST( data->charging_rule_remove, freeGxChargingRuleRemove );
    FD_CALLFREE_LIST( data->charging_rule_install, freeGxChargingRuleInstall );
    FD_CALLFREE_LIST( data->qos_information, freeGxQosInformation );
    FD_CALLFREE_LIST( data->usage_monitoring_information, freeGxUsageMonitoringInformation );
    FD_CALLFREE_STRUCT( data->pra_install, freeGxPraInstall );
    FD_CALLFREE_STRUCT( data->pra_remove, freeGxPraRemove );
    FD_CALLFREE_LIST( data->routing_rule_report, freeGxRoutingRuleReport );
    FD_CALLFREE_LIST( data->conditional_policy_information, freeGxConditionalPolicyInformation );

    FD_FREE_LIST( data->supported_features );
    FD_FREE_LIST( data->event_trigger );
    FD_FREE_LIST( data->redirect_host );
    FD_FREE_LIST( data->charging_rule_remove );
    FD_FREE_LIST( data->charging_rule_install );
    FD_FREE_LIST( data->qos_information );
    FD_FREE_LIST( data->usage_monitoring_information );
    FD_FREE_LIST( data->csg_information_reporting );
    FD_FREE_LIST( data->routing_rule_report );
    FD_FREE_LIST( data->conditional_policy_information );
    FD_FREE_LIST( data->proxy_info );
    FD_FREE_LIST( data->route_record );
    FD_FREE_LIST( data->load );

    return FD_REASON_OK;
}

/*
*
*       Fun:    gx_ccr_free
*
*       Desc:   Free the multiple occurrance AVP's for Credit-Control-Request
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Credit-Control-Request ::= <Diameter Header: 272, REQ, PXY, 16777238>
*              < Session-Id >
*              [ DRMP ]
*              { Auth-Application-Id }
*              { Origin-Host }
*              { Origin-Realm }
*              { Destination-Realm }
*              { CC-Request-Type }
*              { CC-Request-Number }
*              [ Credit-Management-Status ]
*              [ Destination-Host ]
*              [ Origin-State-Id ]
*          *   [ Subscription-Id ]
*              [ OC-Supported-Features ]
*          *   [ Supported-Features ]
*              [ TDF-Information ]
*              [ Network-Request-Support ]
*          *   [ Packet-Filter-Information ]
*              [ Packet-Filter-Operation ]
*              [ Bearer-Identifier ]
*              [ Bearer-Operation ]
*              [ Dynamic-Address-Flag ]
*              [ Dynamic-Address-Flag-Extension ]
*              [ PDN-Connection-Charging-ID ]
*              [ Framed-IP-Address ]
*              [ Framed-IPv6-Prefix ]
*              [ IP-CAN-Type ]
*              [ 3GPP-RAT-Type ]
*              [ AN-Trusted ]
*              [ RAT-Type ]
*              [ Termination-Cause ]
*              [ User-Equipment-Info ]
*              [ QoS-Information ]
*              [ QoS-Negotiation ]
*              [ QoS-Upgrade ]
*              [ Default-EPS-Bearer-QoS ]
*              [ Default-QoS-Information ]
*          * 2 [ AN-GW-Address ]
*              [ AN-GW-Status ]
*              [ 3GPP-SGSN-MCC-MNC ]
*              [ 3GPP-SGSN-Address ]
*              [ 3GPP-SGSN-Ipv6-Address ]
*              [ 3GPP-GGSN-Address ]
*              [ 3GPP-GGSN-Ipv6-Address ]
*              [ 3GPP-Selection-Mode ]
*              [ RAI ]
*              [ 3GPP-User-Location-Info ]
*              [ Fixed-User-Location-Info ]
*              [ User-Location-Info-Time ]
*              [ User-CSG-Information ]
*              [ TWAN-Identifier ]
*              [ 3GPP-MS-TimeZone ]
*          *   [ RAN-NAS-Release-Cause ]
*              [ 3GPP-Charging-Characteristics ]
*              [ Called-Station-Id ]
*              [ PDN-Connection-ID ]
*              [ Bearer-Usage ]
*              [ Online ]
*              [ Offline ]
*          *   [ TFT-Packet-Filter-Information ]
*          *   [ Charging-Rule-Report ]
*          *   [ Application-Detection-Information ]
*          *   [ Event-Trigger ]
*              [ Event-Report-Indication ]
*              [ Access-Network-Charging-Address ]
*          *   [ Access-Network-Charging-Identifier-Gx ]
*          *   [ CoA-Information ]
*          *   [ Usage-Monitoring-Information ]
*              [ NBIFOM-Support ]
*              [ NBIFOM-Mode ]
*              [ Default-Access ]
*              [ Origination-Time-Stamp ]
*              [ Maximum-Wait-Time ]
*              [ Access-Availability-Change-Reason ]
*              [ Routing-Rule-Install ]
*              [ Routing-Rule-Remove ]
*              [ HeNB-Local-IP-Address ]
*              [ UE-Local-IP-Address ]
*              [ UDP-Source-Port ]
*              [ TCP-Source-Port ]
*          *   [ Presence-Reporting-Area-Information ]
*              [ Logical-Access-Id ]
*              [ Physical-Access-Id ]
*          *   [ Proxy-Info ]
*          *   [ Route-Record ]
*              [ 3GPP-PS-Data-Off-Status ]
*          *   [ AVP ]
*/
int gx_ccr_free
(
    GxCCR *data
)
{
    FD_CALLFREE_STRUCT( data->qos_information, freeGxQosInformation );
    FD_CALLFREE_LIST( data->charging_rule_report, freeGxChargingRuleReport );
    FD_CALLFREE_LIST( data->application_detection_information, freeGxApplicationDetectionInformation );
    FD_CALLFREE_STRUCT( data->event_report_indication, freeGxEventReportIndication );
    FD_CALLFREE_LIST( data->access_network_charging_identifier_gx, freeGxAccessNetworkChargingIdentifierGx );
    FD_CALLFREE_LIST( data->coa_information, freeGxCoaInformation );
    FD_CALLFREE_LIST( data->usage_monitoring_information, freeGxUsageMonitoringInformation );
    FD_CALLFREE_STRUCT( data->routing_rule_install, freeGxRoutingRuleInstall );
    FD_CALLFREE_STRUCT( data->routing_rule_remove, freeGxRoutingRuleRemove );

    FD_FREE_LIST( data->subscription_id );
    FD_FREE_LIST( data->supported_features );
    FD_FREE_LIST( data->packet_filter_information );
    FD_FREE_LIST( data->an_gw_address );
    FD_FREE_LIST( data->ran_nas_release_cause );
    FD_FREE_LIST( data->tft_packet_filter_information );
    FD_FREE_LIST( data->charging_rule_report );
    FD_FREE_LIST( data->application_detection_information );
    FD_FREE_LIST( data->event_trigger );
    FD_FREE_LIST( data->access_network_charging_identifier_gx );
    FD_FREE_LIST( data->coa_information );
    FD_FREE_LIST( data->usage_monitoring_information );
    FD_FREE_LIST( data->presence_reporting_area_information );
    FD_FREE_LIST( data->proxy_info );
    FD_FREE_LIST( data->route_record );

    return FD_REASON_OK;
}

/*******************************************************************************/
/* grouped avp parsing functions                                               */
/*******************************************************************************/

/*
*
*       Fun:    parseGxExperimentalResult
*
*       Desc:   Parse Experimental-Result AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Experimental-Result ::= <AVP Header: 297>
*              { Vendor-Id }
*              { Experimental-Result-Code }
*/
static int parseGxExperimentalResult
(
    struct avp *avp,
    GxExperimentalResult *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Experimental-Result child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_vendor_id)) { data->vendor_id = hdr->avp_value->u32; data->presence.vendor_id=1; }
        else if (IS_AVP(davp_experimental_result_code)) { data->experimental_result_code = hdr->avp_value->u32; data->presence.experimental_result_code=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Experimental-Result child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxPraRemove
*
*       Desc:   Parse PRA-Remove AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        PRA-Remove ::= <AVP Header: 2846>
*          *   [ Presence-Reporting-Area-Identifier ]
*          *   [ AVP ]
*/
static int parseGxPraRemove
(
    struct avp *avp,
    GxPraRemove *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the PRA-Remove child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_presence_reporting_area_identifier)) { data->presence_reporting_area_identifier.count++; cnt++; data->presence.presence_reporting_area_identifier=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->presence_reporting_area_identifier, GxPresenceReportingAreaIdentifierOctetString);

        /* iterate through the PRA-Remove child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_presence_reporting_area_identifier)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->presence_reporting_area_identifier.list[data->presence_reporting_area_identifier.count], GX_PRESENCE_REPORTING_AREA_IDENTIFIER_LEN); data->presence_reporting_area_identifier.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxQosInformation
*
*       Desc:   Parse QoS-Information AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        QoS-Information ::= <AVP Header: 1016>
*              [ QoS-Class-Identifier ]
*              [ Max-Requested-Bandwidth-UL ]
*              [ Max-Requested-Bandwidth-DL ]
*              [ Extended-Max-Requested-BW-UL ]
*              [ Extended-Max-Requested-BW-DL ]
*              [ Guaranteed-Bitrate-UL ]
*              [ Guaranteed-Bitrate-DL ]
*              [ Extended-GBR-UL ]
*              [ Extended-GBR-DL ]
*              [ Bearer-Identifier ]
*              [ Allocation-Retention-Priority ]
*              [ APN-Aggregate-Max-Bitrate-UL ]
*              [ APN-Aggregate-Max-Bitrate-DL ]
*              [ Extended-APN-AMBR-UL ]
*              [ Extended-APN-AMBR-DL ]
*          *   [ Conditional-APN-Aggregate-Max-Bitrate ]
*          *   [ AVP ]
*/
static int parseGxQosInformation
(
    struct avp *avp,
    GxQosInformation *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the QoS-Information child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_qos_class_identifier)) { data->qos_class_identifier = hdr->avp_value->i32; data->presence.qos_class_identifier=1; }
        else if (IS_AVP(davp_max_requested_bandwidth_ul)) { data->max_requested_bandwidth_ul = hdr->avp_value->u32; data->presence.max_requested_bandwidth_ul=1; }
        else if (IS_AVP(davp_max_requested_bandwidth_dl)) { data->max_requested_bandwidth_dl = hdr->avp_value->u32; data->presence.max_requested_bandwidth_dl=1; }
        else if (IS_AVP(davp_extended_max_requested_bw_ul)) { data->extended_max_requested_bw_ul = hdr->avp_value->u32; data->presence.extended_max_requested_bw_ul=1; }
        else if (IS_AVP(davp_extended_max_requested_bw_dl)) { data->extended_max_requested_bw_dl = hdr->avp_value->u32; data->presence.extended_max_requested_bw_dl=1; }
        else if (IS_AVP(davp_guaranteed_bitrate_ul)) { data->guaranteed_bitrate_ul = hdr->avp_value->u32; data->presence.guaranteed_bitrate_ul=1; }
        else if (IS_AVP(davp_guaranteed_bitrate_dl)) { data->guaranteed_bitrate_dl = hdr->avp_value->u32; data->presence.guaranteed_bitrate_dl=1; }
        else if (IS_AVP(davp_extended_gbr_ul)) { data->extended_gbr_ul = hdr->avp_value->u32; data->presence.extended_gbr_ul=1; }
        else if (IS_AVP(davp_extended_gbr_dl)) { data->extended_gbr_dl = hdr->avp_value->u32; data->presence.extended_gbr_dl=1; }
        else if (IS_AVP(davp_bearer_identifier)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->bearer_identifier, GX_BEARER_IDENTIFIER_LEN); data->presence.bearer_identifier=1; }
        else if (IS_AVP(davp_allocation_retention_priority)) { FDCHECK_PARSE_DIRECT(parseGxAllocationRetentionPriority, child_avp, &data->allocation_retention_priority); data->presence.allocation_retention_priority=1; }
        else if (IS_AVP(davp_apn_aggregate_max_bitrate_ul)) { data->apn_aggregate_max_bitrate_ul = hdr->avp_value->u32; data->presence.apn_aggregate_max_bitrate_ul=1; }
        else if (IS_AVP(davp_apn_aggregate_max_bitrate_dl)) { data->apn_aggregate_max_bitrate_dl = hdr->avp_value->u32; data->presence.apn_aggregate_max_bitrate_dl=1; }
        else if (IS_AVP(davp_extended_apn_ambr_ul)) { data->extended_apn_ambr_ul = hdr->avp_value->u32; data->presence.extended_apn_ambr_ul=1; }
        else if (IS_AVP(davp_extended_apn_ambr_dl)) { data->extended_apn_ambr_dl = hdr->avp_value->u32; data->presence.extended_apn_ambr_dl=1; }
        else if (IS_AVP(davp_conditional_apn_aggregate_max_bitrate)) { data->conditional_apn_aggregate_max_bitrate.count++; cnt++; data->presence.conditional_apn_aggregate_max_bitrate=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->conditional_apn_aggregate_max_bitrate, GxConditionalApnAggregateMaxBitrate);

        /* iterate through the QoS-Information child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_conditional_apn_aggregate_max_bitrate)) { FDCHECK_PARSE_DIRECT(parseGxConditionalApnAggregateMaxBitrate, child_avp, &data->conditional_apn_aggregate_max_bitrate.list[data->conditional_apn_aggregate_max_bitrate.count]); data->conditional_apn_aggregate_max_bitrate.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxConditionalPolicyInformation
*
*       Desc:   Parse Conditional-Policy-Information AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Conditional-Policy-Information ::= <AVP Header: 2840>
*              [ Execution-Time ]
*              [ Default-EPS-Bearer-QoS ]
*              [ APN-Aggregate-Max-Bitrate-UL ]
*              [ APN-Aggregate-Max-Bitrate-DL ]
*              [ Extended-APN-AMBR-UL ]
*              [ Extended-APN-AMBR-DL ]
*          *   [ Conditional-APN-Aggregate-Max-Bitrate ]
*          *   [ AVP ]
*/
static int parseGxConditionalPolicyInformation
(
    struct avp *avp,
    GxConditionalPolicyInformation *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Conditional-Policy-Information child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_execution_time)) { FD_PARSE_TIME(hdr->avp_value, data->execution_time); data->presence.execution_time=1; }
        else if (IS_AVP(davp_default_eps_bearer_qos)) { FDCHECK_PARSE_DIRECT(parseGxDefaultEpsBearerQos, child_avp, &data->default_eps_bearer_qos); data->presence.default_eps_bearer_qos=1; }
        else if (IS_AVP(davp_apn_aggregate_max_bitrate_ul)) { data->apn_aggregate_max_bitrate_ul = hdr->avp_value->u32; data->presence.apn_aggregate_max_bitrate_ul=1; }
        else if (IS_AVP(davp_apn_aggregate_max_bitrate_dl)) { data->apn_aggregate_max_bitrate_dl = hdr->avp_value->u32; data->presence.apn_aggregate_max_bitrate_dl=1; }
        else if (IS_AVP(davp_extended_apn_ambr_ul)) { data->extended_apn_ambr_ul = hdr->avp_value->u32; data->presence.extended_apn_ambr_ul=1; }
        else if (IS_AVP(davp_extended_apn_ambr_dl)) { data->extended_apn_ambr_dl = hdr->avp_value->u32; data->presence.extended_apn_ambr_dl=1; }
        else if (IS_AVP(davp_conditional_apn_aggregate_max_bitrate)) { data->conditional_apn_aggregate_max_bitrate.count++; cnt++; data->presence.conditional_apn_aggregate_max_bitrate=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->conditional_apn_aggregate_max_bitrate, GxConditionalApnAggregateMaxBitrate);

        /* iterate through the Conditional-Policy-Information child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_conditional_apn_aggregate_max_bitrate)) { FDCHECK_PARSE_DIRECT(parseGxConditionalApnAggregateMaxBitrate, child_avp, &data->conditional_apn_aggregate_max_bitrate.list[data->conditional_apn_aggregate_max_bitrate.count]); data->conditional_apn_aggregate_max_bitrate.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxPraInstall
*
*       Desc:   Parse PRA-Install AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        PRA-Install ::= <AVP Header: 2845>
*          *   [ Presence-Reporting-Area-Information ]
*          *   [ AVP ]
*/
static int parseGxPraInstall
(
    struct avp *avp,
    GxPraInstall *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the PRA-Install child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_presence_reporting_area_information)) { data->presence_reporting_area_information.count++; cnt++; data->presence.presence_reporting_area_information=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->presence_reporting_area_information, GxPresenceReportingAreaInformation);

        /* iterate through the PRA-Install child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_presence_reporting_area_information)) { FDCHECK_PARSE_DIRECT(parseGxPresenceReportingAreaInformation, child_avp, &data->presence_reporting_area_information.list[data->presence_reporting_area_information.count]); data->presence_reporting_area_information.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxAreaScope
*
*       Desc:   Parse Area-Scope AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Area-Scope ::= <AVP Header: 1624>
*          *   [ Cell-Global-Identity ]
*          *   [ E-UTRAN-Cell-Global-Identity ]
*          *   [ Routing-Area-Identity ]
*          *   [ Location-Area-Identity ]
*          *   [ Tracking-Area-Identity ]
*          *   [ AVP ]
*/
static int parseGxAreaScope
(
    struct avp *avp,
    GxAreaScope *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Area-Scope child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_cell_global_identity)) { data->cell_global_identity.count++; cnt++; data->presence.cell_global_identity=1; }
        else if (IS_AVP(davp_e_utran_cell_global_identity)) { data->e_utran_cell_global_identity.count++; cnt++; data->presence.e_utran_cell_global_identity=1; }
        else if (IS_AVP(davp_routing_area_identity)) { data->routing_area_identity.count++; cnt++; data->presence.routing_area_identity=1; }
        else if (IS_AVP(davp_location_area_identity)) { data->location_area_identity.count++; cnt++; data->presence.location_area_identity=1; }
        else if (IS_AVP(davp_tracking_area_identity)) { data->tracking_area_identity.count++; cnt++; data->presence.tracking_area_identity=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->cell_global_identity, GxCellGlobalIdentityOctetString);
        FD_ALLOC_LIST(data->e_utran_cell_global_identity, GxEUtranCellGlobalIdentityOctetString);
        FD_ALLOC_LIST(data->routing_area_identity, GxRoutingAreaIdentityOctetString);
        FD_ALLOC_LIST(data->location_area_identity, GxLocationAreaIdentityOctetString);
        FD_ALLOC_LIST(data->tracking_area_identity, GxTrackingAreaIdentityOctetString);

        /* iterate through the Area-Scope child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_cell_global_identity)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->cell_global_identity.list[data->cell_global_identity.count], GX_CELL_GLOBAL_IDENTITY_LEN); data->cell_global_identity.count++; }
            else if (IS_AVP(davp_e_utran_cell_global_identity)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->e_utran_cell_global_identity.list[data->e_utran_cell_global_identity.count], GX_E_UTRAN_CELL_GLOBAL_IDENTITY_LEN); data->e_utran_cell_global_identity.count++; }
            else if (IS_AVP(davp_routing_area_identity)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->routing_area_identity.list[data->routing_area_identity.count], GX_ROUTING_AREA_IDENTITY_LEN); data->routing_area_identity.count++; }
            else if (IS_AVP(davp_location_area_identity)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->location_area_identity.list[data->location_area_identity.count], GX_LOCATION_AREA_IDENTITY_LEN); data->location_area_identity.count++; }
            else if (IS_AVP(davp_tracking_area_identity)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tracking_area_identity.list[data->tracking_area_identity.count], GX_TRACKING_AREA_IDENTITY_LEN); data->tracking_area_identity.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxFlowInformation
*
*       Desc:   Parse Flow-Information AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Flow-Information ::= <AVP Header: 1058>
*              [ Flow-Description ]
*              [ Packet-Filter-Identifier ]
*              [ Packet-Filter-Usage ]
*              [ ToS-Traffic-Class ]
*              [ Security-Parameter-Index ]
*              [ Flow-Label ]
*              [ Flow-Direction ]
*              [ Routing-Rule-Identifier ]
*          *   [ AVP ]
*/
static int parseGxFlowInformation
(
    struct avp *avp,
    GxFlowInformation *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Flow-Information child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_flow_description)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->flow_description, GX_FLOW_DESCRIPTION_LEN); data->presence.flow_description=1; }
        else if (IS_AVP(davp_packet_filter_identifier)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->packet_filter_identifier, GX_PACKET_FILTER_IDENTIFIER_LEN); data->presence.packet_filter_identifier=1; }
        else if (IS_AVP(davp_packet_filter_usage)) { data->packet_filter_usage = hdr->avp_value->i32; data->presence.packet_filter_usage=1; }
        else if (IS_AVP(davp_tos_traffic_class)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tos_traffic_class, GX_TOS_TRAFFIC_CLASS_LEN); data->presence.tos_traffic_class=1; }
        else if (IS_AVP(davp_security_parameter_index)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->security_parameter_index, GX_SECURITY_PARAMETER_INDEX_LEN); data->presence.security_parameter_index=1; }
        else if (IS_AVP(davp_flow_label)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->flow_label, GX_FLOW_LABEL_LEN); data->presence.flow_label=1; }
        else if (IS_AVP(davp_flow_direction)) { data->flow_direction = hdr->avp_value->i32; data->presence.flow_direction=1; }
        else if (IS_AVP(davp_routing_rule_identifier)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->routing_rule_identifier, GX_ROUTING_RULE_IDENTIFIER_LEN); data->presence.routing_rule_identifier=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Flow-Information child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxTunnelInformation
*
*       Desc:   Parse Tunnel-Information AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Tunnel-Information ::= <AVP Header: 1038>
*              [ Tunnel-Header-Length ]
*              [ Tunnel-Header-Filter ]
*/
static int parseGxTunnelInformation
(
    struct avp *avp,
    GxTunnelInformation *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Tunnel-Information child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_tunnel_header_length)) { data->tunnel_header_length = hdr->avp_value->u32; data->presence.tunnel_header_length=1; }
        else if (IS_AVP(davp_tunnel_header_filter)) { data->tunnel_header_filter.count++; cnt++; data->presence.tunnel_header_filter=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->tunnel_header_filter, GxTunnelHeaderFilterOctetString);

        /* iterate through the Tunnel-Information child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_tunnel_header_filter)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tunnel_header_filter.list[data->tunnel_header_filter.count], GX_TUNNEL_HEADER_FILTER_LEN); data->tunnel_header_filter.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxTftPacketFilterInformation
*
*       Desc:   Parse TFT-Packet-Filter-Information AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        TFT-Packet-Filter-Information ::= <AVP Header: 1013>
*              [ Precedence ]
*              [ TFT-Filter ]
*              [ ToS-Traffic-Class ]
*              [ Security-Parameter-Index ]
*              [ Flow-Label ]
*              [ Flow-Direction ]
*          *   [ AVP ]
*/
static int parseGxTftPacketFilterInformation
(
    struct avp *avp,
    GxTftPacketFilterInformation *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the TFT-Packet-Filter-Information child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_precedence)) { data->precedence = hdr->avp_value->u32; data->presence.precedence=1; }
        else if (IS_AVP(davp_tft_filter)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tft_filter, GX_TFT_FILTER_LEN); data->presence.tft_filter=1; }
        else if (IS_AVP(davp_tos_traffic_class)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tos_traffic_class, GX_TOS_TRAFFIC_CLASS_LEN); data->presence.tos_traffic_class=1; }
        else if (IS_AVP(davp_security_parameter_index)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->security_parameter_index, GX_SECURITY_PARAMETER_INDEX_LEN); data->presence.security_parameter_index=1; }
        else if (IS_AVP(davp_flow_label)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->flow_label, GX_FLOW_LABEL_LEN); data->presence.flow_label=1; }
        else if (IS_AVP(davp_flow_direction)) { data->flow_direction = hdr->avp_value->i32; data->presence.flow_direction=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the TFT-Packet-Filter-Information child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxMbsfnArea
*
*       Desc:   Parse MBSFN-Area AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        MBSFN-Area ::= <AVP Header: 1694>
*              { MBSFN-Area-ID }
*              { Carrier-Frequency }
*          *   [ AVP ]
*/
static int parseGxMbsfnArea
(
    struct avp *avp,
    GxMbsfnArea *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the MBSFN-Area child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_mbsfn_area_id)) { data->mbsfn_area_id = hdr->avp_value->u32; data->presence.mbsfn_area_id=1; }
        else if (IS_AVP(davp_carrier_frequency)) { data->carrier_frequency = hdr->avp_value->u32; data->presence.carrier_frequency=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the MBSFN-Area child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxEventReportIndication
*
*       Desc:   Parse Event-Report-Indication AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Event-Report-Indication ::= <AVP Header: 1033>
*              [ AN-Trusted ]
*          *   [ Event-Trigger ]
*              [ User-CSG-Information ]
*              [ IP-CAN-Type ]
*          * 2 [ AN-GW-Address ]
*              [ 3GPP-SGSN-Address ]
*              [ 3GPP-SGSN-Ipv6-Address ]
*              [ 3GPP-SGSN-MCC-MNC ]
*              [ Framed-IP-Address ]
*              [ RAT-Type ]
*              [ RAI ]
*              [ 3GPP-User-Location-Info ]
*              [ Trace-Data ]
*              [ Trace-Reference ]
*              [ 3GPP2-BSID ]
*              [ 3GPP-MS-TimeZone ]
*              [ Routing-IP-Address ]
*              [ UE-Local-IP-Address ]
*              [ HeNB-Local-IP-Address ]
*              [ UDP-Source-Port ]
*              [ Presence-Reporting-Area-Information ]
*          *   [ AVP ]
*/
static int parseGxEventReportIndication
(
    struct avp *avp,
    GxEventReportIndication *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Event-Report-Indication child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_an_trusted)) { data->an_trusted = hdr->avp_value->i32; data->presence.an_trusted=1; }
        else if (IS_AVP(davp_event_trigger)) { data->event_trigger.count++; cnt++; data->presence.event_trigger=1; }
        else if (IS_AVP(davp_user_csg_information)) { FDCHECK_PARSE_DIRECT(parseGxUserCsgInformation, child_avp, &data->user_csg_information); data->presence.user_csg_information=1; }
        else if (IS_AVP(davp_ip_can_type)) { data->ip_can_type = hdr->avp_value->i32; data->presence.ip_can_type=1; }
        else if (IS_AVP(davp_an_gw_address)) { data->an_gw_address.count++; cnt++; data->presence.an_gw_address=1; }
        else if (IS_AVP(davp_3gpp_sgsn_address)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_sgsn_address, GX_3GPP_SGSN_ADDRESS_LEN); data->presence.tgpp_sgsn_address=1; }
        else if (IS_AVP(davp_3gpp_sgsn_ipv6_address)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_sgsn_ipv6_address, GX_3GPP_SGSN_IPV6_ADDRESS_LEN); data->presence.tgpp_sgsn_ipv6_address=1; }
        else if (IS_AVP(davp_3gpp_sgsn_mcc_mnc)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_sgsn_mcc_mnc, GX_3GPP_SGSN_MCC_MNC_LEN); data->presence.tgpp_sgsn_mcc_mnc=1; }
        else if (IS_AVP(davp_framed_ip_address)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->framed_ip_address, GX_FRAMED_IP_ADDRESS_LEN); data->presence.framed_ip_address=1; }
        else if (IS_AVP(davp_rat_type)) { data->rat_type = hdr->avp_value->i32; data->presence.rat_type=1; }
        else if (IS_AVP(davp_rai)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->rai, GX_RAI_LEN); data->presence.rai=1; }
        else if (IS_AVP(davp_3gpp_user_location_info)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_user_location_info, GX_3GPP_USER_LOCATION_INFO_LEN); data->presence.tgpp_user_location_info=1; }
        else if (IS_AVP(davp_trace_data)) { FDCHECK_PARSE_DIRECT(parseGxTraceData, child_avp, &data->trace_data); data->presence.trace_data=1; }
        else if (IS_AVP(davp_trace_reference)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->trace_reference, GX_TRACE_REFERENCE_LEN); data->presence.trace_reference=1; }
        else if (IS_AVP(davp_3gpp2_bsid)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp2_bsid, GX_3GPP2_BSID_LEN); data->presence.tgpp2_bsid=1; }
        else if (IS_AVP(davp_3gpp_ms_timezone)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tgpp_ms_timezone, GX_3GPP_MS_TIMEZONE_LEN); data->presence.tgpp_ms_timezone=1; }
        else if (IS_AVP(davp_routing_ip_address)) { FD_PARSE_ADDRESS(hdr->avp_value, data->routing_ip_address); data->presence.routing_ip_address=1; }
        else if (IS_AVP(davp_ue_local_ip_address)) { FD_PARSE_ADDRESS(hdr->avp_value, data->ue_local_ip_address); data->presence.ue_local_ip_address=1; }
        else if (IS_AVP(davp_henb_local_ip_address)) { FD_PARSE_ADDRESS(hdr->avp_value, data->henb_local_ip_address); data->presence.henb_local_ip_address=1; }
        else if (IS_AVP(davp_udp_source_port)) { data->udp_source_port = hdr->avp_value->u32; data->presence.udp_source_port=1; }
        else if (IS_AVP(davp_presence_reporting_area_information)) { FDCHECK_PARSE_DIRECT(parseGxPresenceReportingAreaInformation, child_avp, &data->presence_reporting_area_information); data->presence.presence_reporting_area_information=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->event_trigger, int32_t);
        FD_ALLOC_LIST(data->an_gw_address, FdAddress);

        /* iterate through the Event-Report-Indication child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_event_trigger)) { data->event_trigger.list[data->event_trigger.count] = hdr->avp_value->i32; data->event_trigger.count++; }
            else if (IS_AVP(davp_an_gw_address)) { FD_PARSE_ADDRESS(hdr->avp_value, data->an_gw_address.list[data->an_gw_address.count]); data->an_gw_address.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxTdfInformation
*
*       Desc:   Parse TDF-Information AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        TDF-Information ::= <AVP Header: 1087>
*              [ TDF-Destination-Realm ]
*              [ TDF-Destination-Host ]
*              [ TDF-IP-Address ]
*/
static int parseGxTdfInformation
(
    struct avp *avp,
    GxTdfInformation *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the TDF-Information child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_tdf_destination_realm)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tdf_destination_realm, GX_TDF_DESTINATION_REALM_LEN); data->presence.tdf_destination_realm=1; }
        else if (IS_AVP(davp_tdf_destination_host)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tdf_destination_host, GX_TDF_DESTINATION_HOST_LEN); data->presence.tdf_destination_host=1; }
        else if (IS_AVP(davp_tdf_ip_address)) { FD_PARSE_ADDRESS(hdr->avp_value, data->tdf_ip_address); data->presence.tdf_ip_address=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the TDF-Information child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxProxyInfo
*
*       Desc:   Parse Proxy-Info AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Proxy-Info ::= <AVP Header: 284>
*              { Proxy-Host }
*              { Proxy-State }
*          *   [ AVP ]
*/
static int parseGxProxyInfo
(
    struct avp *avp,
    GxProxyInfo *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Proxy-Info child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_proxy_host)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->proxy_host, GX_PROXY_HOST_LEN); data->presence.proxy_host=1; }
        else if (IS_AVP(davp_proxy_state)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->proxy_state, GX_PROXY_STATE_LEN); data->presence.proxy_state=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Proxy-Info child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxUsedServiceUnit
*
*       Desc:   Parse Used-Service-Unit AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Used-Service-Unit ::= <AVP Header: 446>
*              [ Reporting-Reason ]
*              [ Tariff-Change-Usage ]
*              [ CC-Time ]
*              [ CC-Money ]
*              [ CC-Total-Octets ]
*              [ CC-Input-Octets ]
*              [ CC-Output-Octets ]
*              [ CC-Service-Specific-Units ]
*          *   [ Event-Charging-TimeStamp ]
*          *   [ AVP ]
*/
static int parseGxUsedServiceUnit
(
    struct avp *avp,
    GxUsedServiceUnit *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Used-Service-Unit child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_reporting_reason)) { data->reporting_reason = hdr->avp_value->i32; data->presence.reporting_reason=1; }
        else if (IS_AVP(davp_tariff_change_usage)) { data->tariff_change_usage = hdr->avp_value->i32; data->presence.tariff_change_usage=1; }
        else if (IS_AVP(davp_cc_time)) { data->cc_time = hdr->avp_value->u32; data->presence.cc_time=1; }
        else if (IS_AVP(davp_cc_money)) { FDCHECK_PARSE_DIRECT(parseGxCcMoney, child_avp, &data->cc_money); data->presence.cc_money=1; }
        else if (IS_AVP(davp_cc_total_octets)) { data->cc_total_octets = hdr->avp_value->u64; data->presence.cc_total_octets=1; }
        else if (IS_AVP(davp_cc_input_octets)) { data->cc_input_octets = hdr->avp_value->u64; data->presence.cc_input_octets=1; }
        else if (IS_AVP(davp_cc_output_octets)) { data->cc_output_octets = hdr->avp_value->u64; data->presence.cc_output_octets=1; }
        else if (IS_AVP(davp_cc_service_specific_units)) { data->cc_service_specific_units = hdr->avp_value->u64; data->presence.cc_service_specific_units=1; }
        else if (IS_AVP(davp_event_charging_timestamp)) { data->event_charging_timestamp.count++; cnt++; data->presence.event_charging_timestamp=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->event_charging_timestamp, FdTime);

        /* iterate through the Used-Service-Unit child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_event_charging_timestamp)) { FD_PARSE_TIME(hdr->avp_value, data->event_charging_timestamp.list[data->event_charging_timestamp.count]); data->event_charging_timestamp.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxChargingRuleInstall
*
*       Desc:   Parse Charging-Rule-Install AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Charging-Rule-Install ::= <AVP Header: 1001>
*          *   [ Charging-Rule-Definition ]
*          *   [ Charging-Rule-Name ]
*          *   [ Charging-Rule-Base-Name ]
*              [ Bearer-Identifier ]
*              [ Monitoring-Flags ]
*              [ Rule-Activation-Time ]
*              [ Rule-Deactivation-Time ]
*              [ Resource-Allocation-Notification ]
*              [ Charging-Correlation-Indicator ]
*              [ IP-CAN-Type ]
*          *   [ AVP ]
*/
static int parseGxChargingRuleInstall
(
    struct avp *avp,
    GxChargingRuleInstall *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Charging-Rule-Install child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_charging_rule_definition)) { data->charging_rule_definition.count++; cnt++; data->presence.charging_rule_definition=1; }
        else if (IS_AVP(davp_charging_rule_name)) { data->charging_rule_name.count++; cnt++; data->presence.charging_rule_name=1; }
        else if (IS_AVP(davp_charging_rule_base_name)) { data->charging_rule_base_name.count++; cnt++; data->presence.charging_rule_base_name=1; }
        else if (IS_AVP(davp_bearer_identifier)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->bearer_identifier, GX_BEARER_IDENTIFIER_LEN); data->presence.bearer_identifier=1; }
        else if (IS_AVP(davp_monitoring_flags)) { data->monitoring_flags = hdr->avp_value->u32; data->presence.monitoring_flags=1; }
        else if (IS_AVP(davp_rule_activation_time)) { FD_PARSE_TIME(hdr->avp_value, data->rule_activation_time); data->presence.rule_activation_time=1; }
        else if (IS_AVP(davp_rule_deactivation_time)) { FD_PARSE_TIME(hdr->avp_value, data->rule_deactivation_time); data->presence.rule_deactivation_time=1; }
        else if (IS_AVP(davp_resource_allocation_notification)) { data->resource_allocation_notification = hdr->avp_value->i32; data->presence.resource_allocation_notification=1; }
        else if (IS_AVP(davp_charging_correlation_indicator)) { data->charging_correlation_indicator = hdr->avp_value->i32; data->presence.charging_correlation_indicator=1; }
        else if (IS_AVP(davp_ip_can_type)) { data->ip_can_type = hdr->avp_value->i32; data->presence.ip_can_type=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->charging_rule_definition, GxChargingRuleDefinition);
        FD_ALLOC_LIST(data->charging_rule_name, GxChargingRuleNameOctetString);
        FD_ALLOC_LIST(data->charging_rule_base_name, GxChargingRuleBaseNameOctetString);

        /* iterate through the Charging-Rule-Install child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_charging_rule_definition)) { FDCHECK_PARSE_DIRECT(parseGxChargingRuleDefinition, child_avp, &data->charging_rule_definition.list[data->charging_rule_definition.count]); data->charging_rule_definition.count++; }
            else if (IS_AVP(davp_charging_rule_name)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->charging_rule_name.list[data->charging_rule_name.count], GX_CHARGING_RULE_NAME_LEN); data->charging_rule_name.count++; }
            else if (IS_AVP(davp_charging_rule_base_name)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->charging_rule_base_name.list[data->charging_rule_base_name.count], GX_CHARGING_RULE_BASE_NAME_LEN); data->charging_rule_base_name.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxChargingRuleDefinition
*
*       Desc:   Parse Charging-Rule-Definition AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Charging-Rule-Definition ::= <AVP Header: 1003>
*              { Charging-Rule-Name }
*              [ Service-Identifier ]
*              [ Rating-Group ]
*          *   [ Flow-Information ]
*              [ Default-Bearer-Indication ]
*              [ TDF-Application-Identifier ]
*              [ Flow-Status ]
*              [ QoS-Information ]
*              [ PS-to-CS-Session-Continuity ]
*              [ Reporting-Level ]
*              [ Online ]
*              [ Offline ]
*              [ Max-PLR-DL ]
*              [ Max-PLR-UL ]
*              [ Metering-Method ]
*              [ Precedence ]
*              [ AF-Charging-Identifier ]
*          *   [ Flows ]
*              [ Monitoring-Key ]
*              [ Redirect-Information ]
*              [ Mute-Notification ]
*              [ AF-Signalling-Protocol ]
*              [ Sponsor-Identity ]
*              [ Application-Service-Provider-Identity ]
*          *   [ Required-Access-Info ]
*              [ Sharing-Key-DL ]
*              [ Sharing-Key-UL ]
*              [ Traffic-Steering-Policy-Identifier-DL ]
*              [ Traffic-Steering-Policy-Identifier-UL ]
*              [ Content-Version ]
*          *   [ AVP ]
*/
static int parseGxChargingRuleDefinition
(
    struct avp *avp,
    GxChargingRuleDefinition *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Charging-Rule-Definition child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_charging_rule_name)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->charging_rule_name, GX_CHARGING_RULE_NAME_LEN); data->presence.charging_rule_name=1; }
        else if (IS_AVP(davp_service_identifier)) { data->service_identifier = hdr->avp_value->u32; data->presence.service_identifier=1; }
        else if (IS_AVP(davp_rating_group)) { data->rating_group = hdr->avp_value->u32; data->presence.rating_group=1; }
        else if (IS_AVP(davp_flow_information)) { data->flow_information.count++; cnt++; data->presence.flow_information=1; }
        else if (IS_AVP(davp_default_bearer_indication)) { data->default_bearer_indication = hdr->avp_value->i32; data->presence.default_bearer_indication=1; }
        else if (IS_AVP(davp_tdf_application_identifier)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tdf_application_identifier, GX_TDF_APPLICATION_IDENTIFIER_LEN); data->presence.tdf_application_identifier=1; }
        else if (IS_AVP(davp_flow_status)) { data->flow_status = hdr->avp_value->i32; data->presence.flow_status=1; }
        else if (IS_AVP(davp_qos_information)) { FDCHECK_PARSE_DIRECT(parseGxQosInformation, child_avp, &data->qos_information); data->presence.qos_information=1; }
        else if (IS_AVP(davp_ps_to_cs_session_continuity)) { data->ps_to_cs_session_continuity = hdr->avp_value->i32; data->presence.ps_to_cs_session_continuity=1; }
        else if (IS_AVP(davp_reporting_level)) { data->reporting_level = hdr->avp_value->i32; data->presence.reporting_level=1; }
        else if (IS_AVP(davp_online)) { data->online = hdr->avp_value->i32; data->presence.online=1; }
        else if (IS_AVP(davp_offline)) { data->offline = hdr->avp_value->i32; data->presence.offline=1; }
        else if (IS_AVP(davp_max_plr_dl)) { data->max_plr_dl = hdr->avp_value->f32; data->presence.max_plr_dl=1; }
        else if (IS_AVP(davp_max_plr_ul)) { data->max_plr_ul = hdr->avp_value->f32; data->presence.max_plr_ul=1; }
        else if (IS_AVP(davp_metering_method)) { data->metering_method = hdr->avp_value->i32; data->presence.metering_method=1; }
        else if (IS_AVP(davp_precedence)) { data->precedence = hdr->avp_value->u32; data->presence.precedence=1; }
        else if (IS_AVP(davp_af_charging_identifier)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->af_charging_identifier, GX_AF_CHARGING_IDENTIFIER_LEN); data->presence.af_charging_identifier=1; }
        else if (IS_AVP(davp_flows)) { data->flows.count++; cnt++; data->presence.flows=1; }
        else if (IS_AVP(davp_monitoring_key)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->monitoring_key, GX_MONITORING_KEY_LEN); data->presence.monitoring_key=1; }
        else if (IS_AVP(davp_redirect_information)) { FDCHECK_PARSE_DIRECT(parseGxRedirectInformation, child_avp, &data->redirect_information); data->presence.redirect_information=1; }
        else if (IS_AVP(davp_mute_notification)) { data->mute_notification = hdr->avp_value->i32; data->presence.mute_notification=1; }
        else if (IS_AVP(davp_af_signalling_protocol)) { data->af_signalling_protocol = hdr->avp_value->i32; data->presence.af_signalling_protocol=1; }
        else if (IS_AVP(davp_sponsor_identity)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->sponsor_identity, GX_SPONSOR_IDENTITY_LEN); data->presence.sponsor_identity=1; }
        else if (IS_AVP(davp_application_service_provider_identity)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->application_service_provider_identity, GX_APPLICATION_SERVICE_PROVIDER_IDENTITY_LEN); data->presence.application_service_provider_identity=1; }
        else if (IS_AVP(davp_required_access_info)) { data->required_access_info.count++; cnt++; data->presence.required_access_info=1; }
        else if (IS_AVP(davp_sharing_key_dl)) { data->sharing_key_dl = hdr->avp_value->u32; data->presence.sharing_key_dl=1; }
        else if (IS_AVP(davp_sharing_key_ul)) { data->sharing_key_ul = hdr->avp_value->u32; data->presence.sharing_key_ul=1; }
        else if (IS_AVP(davp_traffic_steering_policy_identifier_dl)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->traffic_steering_policy_identifier_dl, GX_TRAFFIC_STEERING_POLICY_IDENTIFIER_DL_LEN); data->presence.traffic_steering_policy_identifier_dl=1; }
        else if (IS_AVP(davp_traffic_steering_policy_identifier_ul)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->traffic_steering_policy_identifier_ul, GX_TRAFFIC_STEERING_POLICY_IDENTIFIER_UL_LEN); data->presence.traffic_steering_policy_identifier_ul=1; }
        else if (IS_AVP(davp_content_version)) { data->content_version = hdr->avp_value->u64; data->presence.content_version=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->flow_information, GxFlowInformation);
        FD_ALLOC_LIST(data->flows, GxFlows);
        FD_ALLOC_LIST(data->required_access_info, int32_t);

        /* iterate through the Charging-Rule-Definition child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_flow_information)) { FDCHECK_PARSE_DIRECT(parseGxFlowInformation, child_avp, &data->flow_information.list[data->flow_information.count]); data->flow_information.count++; }
            else if (IS_AVP(davp_flows)) { FDCHECK_PARSE_DIRECT(parseGxFlows, child_avp, &data->flows.list[data->flows.count]); data->flows.count++; }
            else if (IS_AVP(davp_required_access_info)) { data->required_access_info.list[data->required_access_info.count] = hdr->avp_value->i32; data->required_access_info.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxFinalUnitIndication
*
*       Desc:   Parse Final-Unit-Indication AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Final-Unit-Indication ::= <AVP Header: 430>
*              { Final-Unit-Action }
*          *   [ Restriction-Filter-Rule ]
*          *   [ Filter-Id ]
*              [ Redirect-Server ]
*/
static int parseGxFinalUnitIndication
(
    struct avp *avp,
    GxFinalUnitIndication *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Final-Unit-Indication child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_final_unit_action)) { data->final_unit_action = hdr->avp_value->i32; data->presence.final_unit_action=1; }
        else if (IS_AVP(davp_restriction_filter_rule)) { data->restriction_filter_rule.count++; cnt++; data->presence.restriction_filter_rule=1; }
        else if (IS_AVP(davp_filter_id)) { data->filter_id.count++; cnt++; data->presence.filter_id=1; }
        else if (IS_AVP(davp_redirect_server)) { FDCHECK_PARSE_DIRECT(parseGxRedirectServer, child_avp, &data->redirect_server); data->presence.redirect_server=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->restriction_filter_rule, GxRestrictionFilterRuleOctetString);
        FD_ALLOC_LIST(data->filter_id, GxFilterIdOctetString);

        /* iterate through the Final-Unit-Indication child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_restriction_filter_rule)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->restriction_filter_rule.list[data->restriction_filter_rule.count], GX_RESTRICTION_FILTER_RULE_LEN); data->restriction_filter_rule.count++; }
            else if (IS_AVP(davp_filter_id)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->filter_id.list[data->filter_id.count], GX_FILTER_ID_LEN); data->filter_id.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxUnitValue
*
*       Desc:   Parse Unit-Value AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Unit-Value ::= <AVP Header: 445>
*              { Value-Digits }
*              [ Exponent ]
*/
static int parseGxUnitValue
(
    struct avp *avp,
    GxUnitValue *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Unit-Value child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_value_digits)) { data->value_digits = hdr->avp_value->i64; data->presence.value_digits=1; }
        else if (IS_AVP(davp_exponent)) { data->exponent = hdr->avp_value->i32; data->presence.exponent=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Unit-Value child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxPresenceReportingAreaInformation
*
*       Desc:   Parse Presence-Reporting-Area-Information AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Presence-Reporting-Area-Information ::= <AVP Header: 2822>
*              [ Presence-Reporting-Area-Identifier ]
*              [ Presence-Reporting-Area-Status ]
*              [ Presence-Reporting-Area-Elements-List ]
*              [ Presence-Reporting-Area-Node ]
*          *   [ AVP ]
*/
static int parseGxPresenceReportingAreaInformation
(
    struct avp *avp,
    GxPresenceReportingAreaInformation *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Presence-Reporting-Area-Information child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_presence_reporting_area_identifier)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->presence_reporting_area_identifier, GX_PRESENCE_REPORTING_AREA_IDENTIFIER_LEN); data->presence.presence_reporting_area_identifier=1; }
        else if (IS_AVP(davp_presence_reporting_area_status)) { data->presence_reporting_area_status = hdr->avp_value->u32; data->presence.presence_reporting_area_status=1; }
        else if (IS_AVP(davp_presence_reporting_area_elements_list)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->presence_reporting_area_elements_list, GX_PRESENCE_REPORTING_AREA_ELEMENTS_LIST_LEN); data->presence.presence_reporting_area_elements_list=1; }
        else if (IS_AVP(davp_presence_reporting_area_node)) { data->presence_reporting_area_node = hdr->avp_value->u32; data->presence.presence_reporting_area_node=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Presence-Reporting-Area-Information child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxConditionalApnAggregateMaxBitrate
*
*       Desc:   Parse Conditional-APN-Aggregate-Max-Bitrate AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Conditional-APN-Aggregate-Max-Bitrate ::= <AVP Header: 2818>
*              [ APN-Aggregate-Max-Bitrate-UL ]
*              [ APN-Aggregate-Max-Bitrate-DL ]
*              [ Extended-APN-AMBR-UL ]
*              [ Extended-APN-AMBR-DL ]
*          *   [ IP-CAN-Type ]
*          *   [ RAT-Type ]
*          *   [ AVP ]
*/
static int parseGxConditionalApnAggregateMaxBitrate
(
    struct avp *avp,
    GxConditionalApnAggregateMaxBitrate *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Conditional-APN-Aggregate-Max-Bitrate child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_apn_aggregate_max_bitrate_ul)) { data->apn_aggregate_max_bitrate_ul = hdr->avp_value->u32; data->presence.apn_aggregate_max_bitrate_ul=1; }
        else if (IS_AVP(davp_apn_aggregate_max_bitrate_dl)) { data->apn_aggregate_max_bitrate_dl = hdr->avp_value->u32; data->presence.apn_aggregate_max_bitrate_dl=1; }
        else if (IS_AVP(davp_extended_apn_ambr_ul)) { data->extended_apn_ambr_ul = hdr->avp_value->u32; data->presence.extended_apn_ambr_ul=1; }
        else if (IS_AVP(davp_extended_apn_ambr_dl)) { data->extended_apn_ambr_dl = hdr->avp_value->u32; data->presence.extended_apn_ambr_dl=1; }
        else if (IS_AVP(davp_ip_can_type)) { data->ip_can_type.count++; cnt++; data->presence.ip_can_type=1; }
        else if (IS_AVP(davp_rat_type)) { data->rat_type.count++; cnt++; data->presence.rat_type=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->ip_can_type, int32_t);
        FD_ALLOC_LIST(data->rat_type, int32_t);

        /* iterate through the Conditional-APN-Aggregate-Max-Bitrate child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_ip_can_type)) { data->ip_can_type.list[data->ip_can_type.count] = hdr->avp_value->i32; data->ip_can_type.count++; }
            else if (IS_AVP(davp_rat_type)) { data->rat_type.list[data->rat_type.count] = hdr->avp_value->i32; data->rat_type.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxAccessNetworkChargingIdentifierGx
*
*       Desc:   Parse Access-Network-Charging-Identifier-Gx AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Access-Network-Charging-Identifier-Gx ::= <AVP Header: 1022>
*              { Access-Network-Charging-Identifier-Value }
*          *   [ Charging-Rule-Base-Name ]
*          *   [ Charging-Rule-Name ]
*              [ IP-CAN-Session-Charging-Scope ]
*          *   [ AVP ]
*/
static int parseGxAccessNetworkChargingIdentifierGx
(
    struct avp *avp,
    GxAccessNetworkChargingIdentifierGx *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Access-Network-Charging-Identifier-Gx child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_access_network_charging_identifier_value)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->access_network_charging_identifier_value, GX_ACCESS_NETWORK_CHARGING_IDENTIFIER_VALUE_LEN); data->presence.access_network_charging_identifier_value=1; }
        else if (IS_AVP(davp_charging_rule_base_name)) { data->charging_rule_base_name.count++; cnt++; data->presence.charging_rule_base_name=1; }
        else if (IS_AVP(davp_charging_rule_name)) { data->charging_rule_name.count++; cnt++; data->presence.charging_rule_name=1; }
        else if (IS_AVP(davp_ip_can_session_charging_scope)) { data->ip_can_session_charging_scope = hdr->avp_value->i32; data->presence.ip_can_session_charging_scope=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->charging_rule_base_name, GxChargingRuleBaseNameOctetString);
        FD_ALLOC_LIST(data->charging_rule_name, GxChargingRuleNameOctetString);

        /* iterate through the Access-Network-Charging-Identifier-Gx child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_charging_rule_base_name)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->charging_rule_base_name.list[data->charging_rule_base_name.count], GX_CHARGING_RULE_BASE_NAME_LEN); data->charging_rule_base_name.count++; }
            else if (IS_AVP(davp_charging_rule_name)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->charging_rule_name.list[data->charging_rule_name.count], GX_CHARGING_RULE_NAME_LEN); data->charging_rule_name.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxOcOlr
*
*       Desc:   Parse OC-OLR AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        OC-OLR ::= <AVP Header: 623>
*              < OC-Sequence-Number >
*              < OC-Report-Type >
*              [ OC-Reduction-Percentage ]
*              [ OC-Validity-Duration ]
*          *   [ AVP ]
*/
static int parseGxOcOlr
(
    struct avp *avp,
    GxOcOlr *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the OC-OLR child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_oc_sequence_number)) { data->oc_sequence_number = hdr->avp_value->u64; data->presence.oc_sequence_number=1; }
        else if (IS_AVP(davp_oc_report_type)) { data->oc_report_type = hdr->avp_value->i32; data->presence.oc_report_type=1; }
        else if (IS_AVP(davp_oc_reduction_percentage)) { data->oc_reduction_percentage = hdr->avp_value->u32; data->presence.oc_reduction_percentage=1; }
        else if (IS_AVP(davp_oc_validity_duration)) { data->oc_validity_duration = hdr->avp_value->u32; data->presence.oc_validity_duration=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the OC-OLR child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxRoutingRuleInstall
*
*       Desc:   Parse Routing-Rule-Install AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Routing-Rule-Install ::= <AVP Header: 1081>
*          *   [ Routing-Rule-Definition ]
*          *   [ AVP ]
*/
static int parseGxRoutingRuleInstall
(
    struct avp *avp,
    GxRoutingRuleInstall *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Routing-Rule-Install child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_routing_rule_definition)) { data->routing_rule_definition.count++; cnt++; data->presence.routing_rule_definition=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->routing_rule_definition, GxRoutingRuleDefinition);

        /* iterate through the Routing-Rule-Install child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_routing_rule_definition)) { FDCHECK_PARSE_DIRECT(parseGxRoutingRuleDefinition, child_avp, &data->routing_rule_definition.list[data->routing_rule_definition.count]); data->routing_rule_definition.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxTraceData
*
*       Desc:   Parse Trace-Data AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Trace-Data ::= <AVP Header: 1458>
*              { Trace-Reference }
*              { Trace-Depth }
*              { Trace-NE-Type-List }
*              [ Trace-Interface-List ]
*              { Trace-Event-List }
*              [ OMC-Id ]
*              { Trace-Collection-Entity }
*              [ MDT-Configuration ]
*          *   [ AVP ]
*/
static int parseGxTraceData
(
    struct avp *avp,
    GxTraceData *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Trace-Data child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_trace_reference)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->trace_reference, GX_TRACE_REFERENCE_LEN); data->presence.trace_reference=1; }
        else if (IS_AVP(davp_trace_depth)) { data->trace_depth = hdr->avp_value->i32; data->presence.trace_depth=1; }
        else if (IS_AVP(davp_trace_ne_type_list)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->trace_ne_type_list, GX_TRACE_NE_TYPE_LIST_LEN); data->presence.trace_ne_type_list=1; }
        else if (IS_AVP(davp_trace_interface_list)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->trace_interface_list, GX_TRACE_INTERFACE_LIST_LEN); data->presence.trace_interface_list=1; }
        else if (IS_AVP(davp_trace_event_list)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->trace_event_list, GX_TRACE_EVENT_LIST_LEN); data->presence.trace_event_list=1; }
        else if (IS_AVP(davp_omc_id)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->omc_id, GX_OMC_ID_LEN); data->presence.omc_id=1; }
        else if (IS_AVP(davp_trace_collection_entity)) { FD_PARSE_ADDRESS(hdr->avp_value, data->trace_collection_entity); data->presence.trace_collection_entity=1; }
        else if (IS_AVP(davp_mdt_configuration)) { FDCHECK_PARSE_DIRECT(parseGxMdtConfiguration, child_avp, &data->mdt_configuration); data->presence.mdt_configuration=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Trace-Data child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxRoutingRuleDefinition
*
*       Desc:   Parse Routing-Rule-Definition AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Routing-Rule-Definition ::= <AVP Header: 1076>
*              { Routing-Rule-Identifier }
*          *   [ Routing-Filter ]
*              [ Precedence ]
*              [ Routing-IP-Address ]
*              [ IP-CAN-Type ]
*          *   [ AVP ]
*/
static int parseGxRoutingRuleDefinition
(
    struct avp *avp,
    GxRoutingRuleDefinition *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Routing-Rule-Definition child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_routing_rule_identifier)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->routing_rule_identifier, GX_ROUTING_RULE_IDENTIFIER_LEN); data->presence.routing_rule_identifier=1; }
        else if (IS_AVP(davp_routing_filter)) { data->routing_filter.count++; cnt++; data->presence.routing_filter=1; }
        else if (IS_AVP(davp_precedence)) { data->precedence = hdr->avp_value->u32; data->presence.precedence=1; }
        else if (IS_AVP(davp_routing_ip_address)) { FD_PARSE_ADDRESS(hdr->avp_value, data->routing_ip_address); data->presence.routing_ip_address=1; }
        else if (IS_AVP(davp_ip_can_type)) { data->ip_can_type = hdr->avp_value->i32; data->presence.ip_can_type=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->routing_filter, GxRoutingFilter);

        /* iterate through the Routing-Rule-Definition child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_routing_filter)) { FDCHECK_PARSE_DIRECT(parseGxRoutingFilter, child_avp, &data->routing_filter.list[data->routing_filter.count]); data->routing_filter.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxMdtConfiguration
*
*       Desc:   Parse MDT-Configuration AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        MDT-Configuration ::= <AVP Header: 1622>
*              { Job-Type }
*              [ Area-Scope ]
*              [ List-Of-Measurements ]
*              [ Reporting-Trigger ]
*              [ Report-Interval ]
*              [ Report-Amount ]
*              [ Event-Threshold-RSRP ]
*              [ Event-Threshold-RSRQ ]
*              [ Logging-Interval ]
*              [ Logging-Duration ]
*              [ Measurement-Period-LTE ]
*              [ Measurement-Period-UMTS ]
*              [ Collection-Period-RRM-LTE ]
*              [ Collection-Period-RRM-UMTS ]
*              [ Positioning-Method ]
*              [ Measurement-Quantity ]
*              [ Event-Threshold-Event-1F ]
*              [ Event-Threshold-Event-1I ]
*          *   [ MDT-Allowed-PLMN-Id ]
*          *   [ MBSFN-Area ]
*          *   [ AVP ]
*/
static int parseGxMdtConfiguration
(
    struct avp *avp,
    GxMdtConfiguration *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the MDT-Configuration child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_job_type)) { data->job_type = hdr->avp_value->i32; data->presence.job_type=1; }
        else if (IS_AVP(davp_area_scope)) { FDCHECK_PARSE_DIRECT(parseGxAreaScope, child_avp, &data->area_scope); data->presence.area_scope=1; }
        else if (IS_AVP(davp_list_of_measurements)) { data->list_of_measurements = hdr->avp_value->u32; data->presence.list_of_measurements=1; }
        else if (IS_AVP(davp_reporting_trigger)) { data->reporting_trigger = hdr->avp_value->u32; data->presence.reporting_trigger=1; }
        else if (IS_AVP(davp_report_interval)) { data->report_interval = hdr->avp_value->i32; data->presence.report_interval=1; }
        else if (IS_AVP(davp_report_amount)) { data->report_amount = hdr->avp_value->i32; data->presence.report_amount=1; }
        else if (IS_AVP(davp_event_threshold_rsrp)) { data->event_threshold_rsrp = hdr->avp_value->u32; data->presence.event_threshold_rsrp=1; }
        else if (IS_AVP(davp_event_threshold_rsrq)) { data->event_threshold_rsrq = hdr->avp_value->u32; data->presence.event_threshold_rsrq=1; }
        else if (IS_AVP(davp_logging_interval)) { data->logging_interval = hdr->avp_value->i32; data->presence.logging_interval=1; }
        else if (IS_AVP(davp_logging_duration)) { data->logging_duration = hdr->avp_value->i32; data->presence.logging_duration=1; }
        else if (IS_AVP(davp_measurement_period_lte)) { data->measurement_period_lte = hdr->avp_value->i32; data->presence.measurement_period_lte=1; }
        else if (IS_AVP(davp_measurement_period_umts)) { data->measurement_period_umts = hdr->avp_value->i32; data->presence.measurement_period_umts=1; }
        else if (IS_AVP(davp_collection_period_rrm_lte)) { data->collection_period_rrm_lte = hdr->avp_value->i32; data->presence.collection_period_rrm_lte=1; }
        else if (IS_AVP(davp_collection_period_rrm_umts)) { data->collection_period_rrm_umts = hdr->avp_value->i32; data->presence.collection_period_rrm_umts=1; }
        else if (IS_AVP(davp_positioning_method)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->positioning_method, GX_POSITIONING_METHOD_LEN); data->presence.positioning_method=1; }
        else if (IS_AVP(davp_measurement_quantity)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->measurement_quantity, GX_MEASUREMENT_QUANTITY_LEN); data->presence.measurement_quantity=1; }
        else if (IS_AVP(davp_event_threshold_event_1f)) { data->event_threshold_event_1f = hdr->avp_value->i32; data->presence.event_threshold_event_1f=1; }
        else if (IS_AVP(davp_event_threshold_event_1i)) { data->event_threshold_event_1i = hdr->avp_value->i32; data->presence.event_threshold_event_1i=1; }
        else if (IS_AVP(davp_mdt_allowed_plmn_id)) { data->mdt_allowed_plmn_id.count++; cnt++; data->presence.mdt_allowed_plmn_id=1; }
        else if (IS_AVP(davp_mbsfn_area)) { data->mbsfn_area.count++; cnt++; data->presence.mbsfn_area=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->mdt_allowed_plmn_id, GxMdtAllowedPlmnIdOctetString);
        FD_ALLOC_LIST(data->mbsfn_area, GxMbsfnArea);

        /* iterate through the MDT-Configuration child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_mdt_allowed_plmn_id)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->mdt_allowed_plmn_id.list[data->mdt_allowed_plmn_id.count], GX_MDT_ALLOWED_PLMN_ID_LEN); data->mdt_allowed_plmn_id.count++; }
            else if (IS_AVP(davp_mbsfn_area)) { FDCHECK_PARSE_DIRECT(parseGxMbsfnArea, child_avp, &data->mbsfn_area.list[data->mbsfn_area.count]); data->mbsfn_area.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxChargingRuleRemove
*
*       Desc:   Parse Charging-Rule-Remove AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Charging-Rule-Remove ::= <AVP Header: 1002>
*          *   [ Charging-Rule-Name ]
*          *   [ Charging-Rule-Base-Name ]
*          *   [ Required-Access-Info ]
*              [ Resource-Release-Notification ]
*          *   [ AVP ]
*/
static int parseGxChargingRuleRemove
(
    struct avp *avp,
    GxChargingRuleRemove *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Charging-Rule-Remove child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_charging_rule_name)) { data->charging_rule_name.count++; cnt++; data->presence.charging_rule_name=1; }
        else if (IS_AVP(davp_charging_rule_base_name)) { data->charging_rule_base_name.count++; cnt++; data->presence.charging_rule_base_name=1; }
        else if (IS_AVP(davp_required_access_info)) { data->required_access_info.count++; cnt++; data->presence.required_access_info=1; }
        else if (IS_AVP(davp_resource_release_notification)) { data->resource_release_notification = hdr->avp_value->i32; data->presence.resource_release_notification=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->charging_rule_name, GxChargingRuleNameOctetString);
        FD_ALLOC_LIST(data->charging_rule_base_name, GxChargingRuleBaseNameOctetString);
        FD_ALLOC_LIST(data->required_access_info, int32_t);

        /* iterate through the Charging-Rule-Remove child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_charging_rule_name)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->charging_rule_name.list[data->charging_rule_name.count], GX_CHARGING_RULE_NAME_LEN); data->charging_rule_name.count++; }
            else if (IS_AVP(davp_charging_rule_base_name)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->charging_rule_base_name.list[data->charging_rule_base_name.count], GX_CHARGING_RULE_BASE_NAME_LEN); data->charging_rule_base_name.count++; }
            else if (IS_AVP(davp_required_access_info)) { data->required_access_info.list[data->required_access_info.count] = hdr->avp_value->i32; data->required_access_info.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxAllocationRetentionPriority
*
*       Desc:   Parse Allocation-Retention-Priority AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Allocation-Retention-Priority ::= <AVP Header: 1034>
*              { Priority-Level }
*              [ Pre-emption-Capability ]
*              [ Pre-emption-Vulnerability ]
*/
static int parseGxAllocationRetentionPriority
(
    struct avp *avp,
    GxAllocationRetentionPriority *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Allocation-Retention-Priority child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_priority_level)) { data->priority_level = hdr->avp_value->u32; data->presence.priority_level=1; }
        else if (IS_AVP(davp_pre_emption_capability)) { data->pre_emption_capability = hdr->avp_value->i32; data->presence.pre_emption_capability=1; }
        else if (IS_AVP(davp_pre_emption_vulnerability)) { data->pre_emption_vulnerability = hdr->avp_value->i32; data->presence.pre_emption_vulnerability=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Allocation-Retention-Priority child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxDefaultEpsBearerQos
*
*       Desc:   Parse Default-EPS-Bearer-QoS AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Default-EPS-Bearer-QoS ::= <AVP Header: 1049>
*              [ QoS-Class-Identifier ]
*              [ Allocation-Retention-Priority ]
*          *   [ AVP ]
*/
static int parseGxDefaultEpsBearerQos
(
    struct avp *avp,
    GxDefaultEpsBearerQos *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Default-EPS-Bearer-QoS child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_qos_class_identifier)) { data->qos_class_identifier = hdr->avp_value->i32; data->presence.qos_class_identifier=1; }
        else if (IS_AVP(davp_allocation_retention_priority)) { FDCHECK_PARSE_DIRECT(parseGxAllocationRetentionPriority, child_avp, &data->allocation_retention_priority); data->presence.allocation_retention_priority=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Default-EPS-Bearer-QoS child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxRoutingRuleReport
*
*       Desc:   Parse Routing-Rule-Report AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Routing-Rule-Report ::= <AVP Header: 2835>
*          *   [ Routing-Rule-Identifier ]
*              [ PCC-Rule-Status ]
*              [ Routing-Rule-Failure-Code ]
*          *   [ AVP ]
*/
static int parseGxRoutingRuleReport
(
    struct avp *avp,
    GxRoutingRuleReport *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Routing-Rule-Report child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_routing_rule_identifier)) { data->routing_rule_identifier.count++; cnt++; data->presence.routing_rule_identifier=1; }
        else if (IS_AVP(davp_pcc_rule_status)) { data->pcc_rule_status = hdr->avp_value->i32; data->presence.pcc_rule_status=1; }
        else if (IS_AVP(davp_routing_rule_failure_code)) { data->routing_rule_failure_code = hdr->avp_value->u32; data->presence.routing_rule_failure_code=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->routing_rule_identifier, GxRoutingRuleIdentifierOctetString);

        /* iterate through the Routing-Rule-Report child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_routing_rule_identifier)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->routing_rule_identifier.list[data->routing_rule_identifier.count], GX_ROUTING_RULE_IDENTIFIER_LEN); data->routing_rule_identifier.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxUserEquipmentInfo
*
*       Desc:   Parse User-Equipment-Info AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        User-Equipment-Info ::= <AVP Header: 458>
*              { User-Equipment-Info-Type }
*              { User-Equipment-Info-Value }
*/
static int parseGxUserEquipmentInfo
(
    struct avp *avp,
    GxUserEquipmentInfo *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the User-Equipment-Info child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_user_equipment_info_type)) { data->user_equipment_info_type = hdr->avp_value->i32; data->presence.user_equipment_info_type=1; }
        else if (IS_AVP(davp_user_equipment_info_value)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->user_equipment_info_value, GX_USER_EQUIPMENT_INFO_VALUE_LEN); data->presence.user_equipment_info_value=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the User-Equipment-Info child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxSupportedFeatures
*
*       Desc:   Parse Supported-Features AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Supported-Features ::= <AVP Header: 628>
*              { Vendor-Id }
*              { Feature-List-ID }
*              { Feature-List }
*          *   [ AVP ]
*/
static int parseGxSupportedFeatures
(
    struct avp *avp,
    GxSupportedFeatures *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Supported-Features child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_vendor_id)) { data->vendor_id = hdr->avp_value->u32; data->presence.vendor_id=1; }
        else if (IS_AVP(davp_feature_list_id)) { data->feature_list_id = hdr->avp_value->u32; data->presence.feature_list_id=1; }
        else if (IS_AVP(davp_feature_list)) { data->feature_list = hdr->avp_value->u32; data->presence.feature_list=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Supported-Features child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxFixedUserLocationInfo
*
*       Desc:   Parse Fixed-User-Location-Info AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Fixed-User-Location-Info ::= <AVP Header: 2825>
*              [ SSID ]
*              [ BSSID ]
*              [ Logical-Access-Id ]
*              [ Physical-Access-Id ]
*          *   [ AVP ]
*/
static int parseGxFixedUserLocationInfo
(
    struct avp *avp,
    GxFixedUserLocationInfo *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Fixed-User-Location-Info child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_ssid)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->ssid, GX_SSID_LEN); data->presence.ssid=1; }
        else if (IS_AVP(davp_bssid)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->bssid, GX_BSSID_LEN); data->presence.bssid=1; }
        else if (IS_AVP(davp_logical_access_id)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->logical_access_id, GX_LOGICAL_ACCESS_ID_LEN); data->presence.logical_access_id=1; }
        else if (IS_AVP(davp_physical_access_id)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->physical_access_id, GX_PHYSICAL_ACCESS_ID_LEN); data->presence.physical_access_id=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Fixed-User-Location-Info child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxDefaultQosInformation
*
*       Desc:   Parse Default-QoS-Information AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Default-QoS-Information ::= <AVP Header: 2816>
*              [ QoS-Class-Identifier ]
*              [ Max-Requested-Bandwidth-UL ]
*              [ Max-Requested-Bandwidth-DL ]
*              [ Default-QoS-Name ]
*          *   [ AVP ]
*/
static int parseGxDefaultQosInformation
(
    struct avp *avp,
    GxDefaultQosInformation *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Default-QoS-Information child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_qos_class_identifier)) { data->qos_class_identifier = hdr->avp_value->i32; data->presence.qos_class_identifier=1; }
        else if (IS_AVP(davp_max_requested_bandwidth_ul)) { data->max_requested_bandwidth_ul = hdr->avp_value->u32; data->presence.max_requested_bandwidth_ul=1; }
        else if (IS_AVP(davp_max_requested_bandwidth_dl)) { data->max_requested_bandwidth_dl = hdr->avp_value->u32; data->presence.max_requested_bandwidth_dl=1; }
        else if (IS_AVP(davp_default_qos_name)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->default_qos_name, GX_DEFAULT_QOS_NAME_LEN); data->presence.default_qos_name=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Default-QoS-Information child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxLoad
*
*       Desc:   Parse Load AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Load ::= <AVP Header: 650>
*              [ Load-Type ]
*              [ Load-Value ]
*              [ SourceID ]
*          *   [ AVP ]
*/
static int parseGxLoad
(
    struct avp *avp,
    GxLoad *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Load child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_load_type)) { data->load_type = hdr->avp_value->i32; data->presence.load_type=1; }
        else if (IS_AVP(davp_load_value)) { data->load_value = hdr->avp_value->u64; data->presence.load_value=1; }
        else if (IS_AVP(davp_sourceid)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->sourceid, GX_SOURCEID_LEN); data->presence.sourceid=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Load child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxRedirectServer
*
*       Desc:   Parse Redirect-Server AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Redirect-Server ::= <AVP Header: 434>
*              { Redirect-Address-Type }
*              { Redirect-Server-Address }
*/
static int parseGxRedirectServer
(
    struct avp *avp,
    GxRedirectServer *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Redirect-Server child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_redirect_address_type)) { data->redirect_address_type = hdr->avp_value->i32; data->presence.redirect_address_type=1; }
        else if (IS_AVP(davp_redirect_server_address)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->redirect_server_address, GX_REDIRECT_SERVER_ADDRESS_LEN); data->presence.redirect_server_address=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Redirect-Server child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxOcSupportedFeatures
*
*       Desc:   Parse OC-Supported-Features AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        OC-Supported-Features ::= <AVP Header: 621>
*              [ OC-Feature-Vector ]
*          *   [ AVP ]
*/
static int parseGxOcSupportedFeatures
(
    struct avp *avp,
    GxOcSupportedFeatures *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the OC-Supported-Features child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_oc_feature_vector)) { data->oc_feature_vector = hdr->avp_value->u64; data->presence.oc_feature_vector=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the OC-Supported-Features child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxPacketFilterInformation
*
*       Desc:   Parse Packet-Filter-Information AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Packet-Filter-Information ::= <AVP Header: 1061>
*              [ Packet-Filter-Identifier ]
*              [ Precedence ]
*              [ Packet-Filter-Content ]
*              [ ToS-Traffic-Class ]
*              [ Security-Parameter-Index ]
*              [ Flow-Label ]
*              [ Flow-Direction ]
*          *   [ AVP ]
*/
static int parseGxPacketFilterInformation
(
    struct avp *avp,
    GxPacketFilterInformation *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Packet-Filter-Information child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_packet_filter_identifier)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->packet_filter_identifier, GX_PACKET_FILTER_IDENTIFIER_LEN); data->presence.packet_filter_identifier=1; }
        else if (IS_AVP(davp_precedence)) { data->precedence = hdr->avp_value->u32; data->presence.precedence=1; }
        else if (IS_AVP(davp_packet_filter_content)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->packet_filter_content, GX_PACKET_FILTER_CONTENT_LEN); data->presence.packet_filter_content=1; }
        else if (IS_AVP(davp_tos_traffic_class)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tos_traffic_class, GX_TOS_TRAFFIC_CLASS_LEN); data->presence.tos_traffic_class=1; }
        else if (IS_AVP(davp_security_parameter_index)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->security_parameter_index, GX_SECURITY_PARAMETER_INDEX_LEN); data->presence.security_parameter_index=1; }
        else if (IS_AVP(davp_flow_label)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->flow_label, GX_FLOW_LABEL_LEN); data->presence.flow_label=1; }
        else if (IS_AVP(davp_flow_direction)) { data->flow_direction = hdr->avp_value->i32; data->presence.flow_direction=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Packet-Filter-Information child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxSubscriptionId
*
*       Desc:   Parse Subscription-Id AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Subscription-Id ::= <AVP Header: 443>
*              [ Subscription-Id-Type ]
*              [ Subscription-Id-Data ]
*/
static int parseGxSubscriptionId
(
    struct avp *avp,
    GxSubscriptionId *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Subscription-Id child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_subscription_id_type)) { data->subscription_id_type = hdr->avp_value->i32; data->presence.subscription_id_type=1; }
        else if (IS_AVP(davp_subscription_id_data)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->subscription_id_data, GX_SUBSCRIPTION_ID_DATA_LEN); data->presence.subscription_id_data=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Subscription-Id child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxChargingInformation
*
*       Desc:   Parse Charging-Information AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Charging-Information ::= <AVP Header: 618>
*              [ Primary-Event-Charging-Function-Name ]
*              [ Secondary-Event-Charging-Function-Name ]
*              [ Primary-Charging-Collection-Function-Name ]
*              [ Secondary-Charging-Collection-Function-Name ]
*          *   [ AVP ]
*/
static int parseGxChargingInformation
(
    struct avp *avp,
    GxChargingInformation *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Charging-Information child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_primary_event_charging_function_name)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->primary_event_charging_function_name, GX_PRIMARY_EVENT_CHARGING_FUNCTION_NAME_LEN); data->presence.primary_event_charging_function_name=1; }
        else if (IS_AVP(davp_secondary_event_charging_function_name)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->secondary_event_charging_function_name, GX_SECONDARY_EVENT_CHARGING_FUNCTION_NAME_LEN); data->presence.secondary_event_charging_function_name=1; }
        else if (IS_AVP(davp_primary_charging_collection_function_name)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->primary_charging_collection_function_name, GX_PRIMARY_CHARGING_COLLECTION_FUNCTION_NAME_LEN); data->presence.primary_charging_collection_function_name=1; }
        else if (IS_AVP(davp_secondary_charging_collection_function_name)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->secondary_charging_collection_function_name, GX_SECONDARY_CHARGING_COLLECTION_FUNCTION_NAME_LEN); data->presence.secondary_charging_collection_function_name=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Charging-Information child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxUsageMonitoringInformation
*
*       Desc:   Parse Usage-Monitoring-Information AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Usage-Monitoring-Information ::= <AVP Header: 1067>
*              [ Monitoring-Key ]
*          * 2 [ Granted-Service-Unit ]
*          * 2 [ Used-Service-Unit ]
*              [ Quota-Consumption-Time ]
*              [ Usage-Monitoring-Level ]
*              [ Usage-Monitoring-Report ]
*              [ Usage-Monitoring-Support ]
*          *   [ AVP ]
*/
static int parseGxUsageMonitoringInformation
(
    struct avp *avp,
    GxUsageMonitoringInformation *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Usage-Monitoring-Information child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_monitoring_key)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->monitoring_key, GX_MONITORING_KEY_LEN); data->presence.monitoring_key=1; }
        else if (IS_AVP(davp_granted_service_unit)) { data->granted_service_unit.count++; cnt++; data->presence.granted_service_unit=1; }
        else if (IS_AVP(davp_used_service_unit)) { data->used_service_unit.count++; cnt++; data->presence.used_service_unit=1; }
        else if (IS_AVP(davp_quota_consumption_time)) { data->quota_consumption_time = hdr->avp_value->u32; data->presence.quota_consumption_time=1; }
        else if (IS_AVP(davp_usage_monitoring_level)) { data->usage_monitoring_level = hdr->avp_value->i32; data->presence.usage_monitoring_level=1; }
        else if (IS_AVP(davp_usage_monitoring_report)) { data->usage_monitoring_report = hdr->avp_value->i32; data->presence.usage_monitoring_report=1; }
        else if (IS_AVP(davp_usage_monitoring_support)) { data->usage_monitoring_support = hdr->avp_value->i32; data->presence.usage_monitoring_support=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->granted_service_unit, GxGrantedServiceUnit);
        FD_ALLOC_LIST(data->used_service_unit, GxUsedServiceUnit);

        /* iterate through the Usage-Monitoring-Information child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_granted_service_unit)) { FDCHECK_PARSE_DIRECT(parseGxGrantedServiceUnit, child_avp, &data->granted_service_unit.list[data->granted_service_unit.count]); data->granted_service_unit.count++; }
            else if (IS_AVP(davp_used_service_unit)) { FDCHECK_PARSE_DIRECT(parseGxUsedServiceUnit, child_avp, &data->used_service_unit.list[data->used_service_unit.count]); data->used_service_unit.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxChargingRuleReport
*
*       Desc:   Parse Charging-Rule-Report AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Charging-Rule-Report ::= <AVP Header: 1018>
*          *   [ Charging-Rule-Name ]
*          *   [ Charging-Rule-Base-Name ]
*              [ Bearer-Identifier ]
*              [ PCC-Rule-Status ]
*              [ Rule-Failure-Code ]
*              [ Final-Unit-Indication ]
*          *   [ RAN-NAS-Release-Cause ]
*          *   [ Content-Version ]
*          *   [ AVP ]
*/
static int parseGxChargingRuleReport
(
    struct avp *avp,
    GxChargingRuleReport *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Charging-Rule-Report child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_charging_rule_name)) { data->charging_rule_name.count++; cnt++; data->presence.charging_rule_name=1; }
        else if (IS_AVP(davp_charging_rule_base_name)) { data->charging_rule_base_name.count++; cnt++; data->presence.charging_rule_base_name=1; }
        else if (IS_AVP(davp_bearer_identifier)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->bearer_identifier, GX_BEARER_IDENTIFIER_LEN); data->presence.bearer_identifier=1; }
        else if (IS_AVP(davp_pcc_rule_status)) { data->pcc_rule_status = hdr->avp_value->i32; data->presence.pcc_rule_status=1; }
        else if (IS_AVP(davp_rule_failure_code)) { data->rule_failure_code = hdr->avp_value->i32; data->presence.rule_failure_code=1; }
        else if (IS_AVP(davp_final_unit_indication)) { FDCHECK_PARSE_DIRECT(parseGxFinalUnitIndication, child_avp, &data->final_unit_indication); data->presence.final_unit_indication=1; }
        else if (IS_AVP(davp_ran_nas_release_cause)) { data->ran_nas_release_cause.count++; cnt++; data->presence.ran_nas_release_cause=1; }
        else if (IS_AVP(davp_content_version)) { data->content_version.count++; cnt++; data->presence.content_version=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->charging_rule_name, GxChargingRuleNameOctetString);
        FD_ALLOC_LIST(data->charging_rule_base_name, GxChargingRuleBaseNameOctetString);
        FD_ALLOC_LIST(data->ran_nas_release_cause, GxRanNasReleaseCauseOctetString);
        FD_ALLOC_LIST(data->content_version, uint64_t);

        /* iterate through the Charging-Rule-Report child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_charging_rule_name)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->charging_rule_name.list[data->charging_rule_name.count], GX_CHARGING_RULE_NAME_LEN); data->charging_rule_name.count++; }
            else if (IS_AVP(davp_charging_rule_base_name)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->charging_rule_base_name.list[data->charging_rule_base_name.count], GX_CHARGING_RULE_BASE_NAME_LEN); data->charging_rule_base_name.count++; }
            else if (IS_AVP(davp_ran_nas_release_cause)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->ran_nas_release_cause.list[data->ran_nas_release_cause.count], GX_RAN_NAS_RELEASE_CAUSE_LEN); data->ran_nas_release_cause.count++; }
            else if (IS_AVP(davp_content_version)) { data->content_version.list[data->content_version.count] = hdr->avp_value->u64; data->content_version.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxRedirectInformation
*
*       Desc:   Parse Redirect-Information AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Redirect-Information ::= <AVP Header: 1085>
*              [ Redirect-Support ]
*              [ Redirect-Address-Type ]
*              [ Redirect-Server-Address ]
*          *   [ AVP ]
*/
static int parseGxRedirectInformation
(
    struct avp *avp,
    GxRedirectInformation *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Redirect-Information child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_redirect_support)) { data->redirect_support = hdr->avp_value->i32; data->presence.redirect_support=1; }
        else if (IS_AVP(davp_redirect_address_type)) { data->redirect_address_type = hdr->avp_value->i32; data->presence.redirect_address_type=1; }
        else if (IS_AVP(davp_redirect_server_address)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->redirect_server_address, GX_REDIRECT_SERVER_ADDRESS_LEN); data->presence.redirect_server_address=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Redirect-Information child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxFailedAvp
*
*       Desc:   Parse Failed-AVP AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Failed-AVP ::= <AVP Header: 279>
*         1*   { AVP }
*/
static int parseGxFailedAvp
(
    struct avp *avp,
    GxFailedAvp *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Failed-AVP child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        // TODO - To be implemented by developer as this a *[AVP] only Grouped AVP
         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Failed-AVP child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxRoutingRuleRemove
*
*       Desc:   Parse Routing-Rule-Remove AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Routing-Rule-Remove ::= <AVP Header: 1075>
*          *   [ Routing-Rule-Identifier ]
*          *   [ AVP ]
*/
static int parseGxRoutingRuleRemove
(
    struct avp *avp,
    GxRoutingRuleRemove *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Routing-Rule-Remove child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_routing_rule_identifier)) { data->routing_rule_identifier.count++; cnt++; data->presence.routing_rule_identifier=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->routing_rule_identifier, GxRoutingRuleIdentifierOctetString);

        /* iterate through the Routing-Rule-Remove child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_routing_rule_identifier)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->routing_rule_identifier.list[data->routing_rule_identifier.count], GX_ROUTING_RULE_IDENTIFIER_LEN); data->routing_rule_identifier.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxRoutingFilter
*
*       Desc:   Parse Routing-Filter AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Routing-Filter ::= <AVP Header: 1078>
*              { Flow-Description }
*              { Flow-Direction }
*              [ ToS-Traffic-Class ]
*              [ Security-Parameter-Index ]
*              [ Flow-Label ]
*          *   [ AVP ]
*/
static int parseGxRoutingFilter
(
    struct avp *avp,
    GxRoutingFilter *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Routing-Filter child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_flow_description)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->flow_description, GX_FLOW_DESCRIPTION_LEN); data->presence.flow_description=1; }
        else if (IS_AVP(davp_flow_direction)) { data->flow_direction = hdr->avp_value->i32; data->presence.flow_direction=1; }
        else if (IS_AVP(davp_tos_traffic_class)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tos_traffic_class, GX_TOS_TRAFFIC_CLASS_LEN); data->presence.tos_traffic_class=1; }
        else if (IS_AVP(davp_security_parameter_index)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->security_parameter_index, GX_SECURITY_PARAMETER_INDEX_LEN); data->presence.security_parameter_index=1; }
        else if (IS_AVP(davp_flow_label)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->flow_label, GX_FLOW_LABEL_LEN); data->presence.flow_label=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Routing-Filter child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxCoaInformation
*
*       Desc:   Parse CoA-Information AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        CoA-Information ::= <AVP Header: 1039>
*              { Tunnel-Information }
*              { CoA-IP-Address }
*          *   [ AVP ]
*/
static int parseGxCoaInformation
(
    struct avp *avp,
    GxCoaInformation *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the CoA-Information child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_tunnel_information)) { FDCHECK_PARSE_DIRECT(parseGxTunnelInformation, child_avp, &data->tunnel_information); data->presence.tunnel_information=1; }
        else if (IS_AVP(davp_coa_ip_address)) { FD_PARSE_ADDRESS(hdr->avp_value, data->coa_ip_address); data->presence.coa_ip_address=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the CoA-Information child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxGrantedServiceUnit
*
*       Desc:   Parse Granted-Service-Unit AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Granted-Service-Unit ::= <AVP Header: 431>
*              [ Tariff-Time-Change ]
*              [ CC-Time ]
*              [ CC-Money ]
*              [ CC-Total-Octets ]
*              [ CC-Input-Octets ]
*              [ CC-Output-Octets ]
*              [ CC-Service-Specific-Units ]
*          *   [ AVP ]
*/
static int parseGxGrantedServiceUnit
(
    struct avp *avp,
    GxGrantedServiceUnit *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Granted-Service-Unit child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_tariff_time_change)) { FD_PARSE_TIME(hdr->avp_value, data->tariff_time_change); data->presence.tariff_time_change=1; }
        else if (IS_AVP(davp_cc_time)) { data->cc_time = hdr->avp_value->u32; data->presence.cc_time=1; }
        else if (IS_AVP(davp_cc_money)) { FDCHECK_PARSE_DIRECT(parseGxCcMoney, child_avp, &data->cc_money); data->presence.cc_money=1; }
        else if (IS_AVP(davp_cc_total_octets)) { data->cc_total_octets = hdr->avp_value->u64; data->presence.cc_total_octets=1; }
        else if (IS_AVP(davp_cc_input_octets)) { data->cc_input_octets = hdr->avp_value->u64; data->presence.cc_input_octets=1; }
        else if (IS_AVP(davp_cc_output_octets)) { data->cc_output_octets = hdr->avp_value->u64; data->presence.cc_output_octets=1; }
        else if (IS_AVP(davp_cc_service_specific_units)) { data->cc_service_specific_units = hdr->avp_value->u64; data->presence.cc_service_specific_units=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the Granted-Service-Unit child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxCcMoney
*
*       Desc:   Parse CC-Money AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        CC-Money ::= <AVP Header: 413>
*              { Unit-Value }
*              [ Currency-Code ]
*/
static int parseGxCcMoney
(
    struct avp *avp,
    GxCcMoney *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the CC-Money child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_unit_value)) { FDCHECK_PARSE_DIRECT(parseGxUnitValue, child_avp, &data->unit_value); data->presence.unit_value=1; }
        else if (IS_AVP(davp_currency_code)) { data->currency_code = hdr->avp_value->u32; data->presence.currency_code=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the CC-Money child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxApplicationDetectionInformation
*
*       Desc:   Parse Application-Detection-Information AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Application-Detection-Information ::= <AVP Header: 1098>
*              { TDF-Application-Identifier }
*              [ TDF-Application-Instance-Identifier ]
*          *   [ Flow-Information ]
*          *   [ AVP ]
*/
static int parseGxApplicationDetectionInformation
(
    struct avp *avp,
    GxApplicationDetectionInformation *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Application-Detection-Information child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_tdf_application_identifier)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tdf_application_identifier, GX_TDF_APPLICATION_IDENTIFIER_LEN); data->presence.tdf_application_identifier=1; }
        else if (IS_AVP(davp_tdf_application_instance_identifier)) { FD_PARSE_OCTETSTRING(hdr->avp_value, data->tdf_application_instance_identifier, GX_TDF_APPLICATION_INSTANCE_IDENTIFIER_LEN); data->presence.tdf_application_instance_identifier=1; }
        else if (IS_AVP(davp_flow_information)) { data->flow_information.count++; cnt++; data->presence.flow_information=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->flow_information, GxFlowInformation);

        /* iterate through the Application-Detection-Information child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_flow_information)) { FDCHECK_PARSE_DIRECT(parseGxFlowInformation, child_avp, &data->flow_information.list[data->flow_information.count]); data->flow_information.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxFlows
*
*       Desc:   Parse Flows AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Flows ::= <AVP Header: 510>
*              { Media-Component-Number }
*          *   [ Flow-Number ]
*          *   [ Content-Version ]
*              [ Final-Unit-Action ]
*              [ Media-Component-Status ]
*          *   [ AVP ]
*/
static int parseGxFlows
(
    struct avp *avp,
    GxFlows *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the Flows child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_media_component_number)) { data->media_component_number = hdr->avp_value->u32; data->presence.media_component_number=1; }
        else if (IS_AVP(davp_flow_number)) { data->flow_number.count++; cnt++; data->presence.flow_number=1; }
        else if (IS_AVP(davp_content_version)) { data->content_version.count++; cnt++; data->presence.content_version=1; }
        else if (IS_AVP(davp_final_unit_action)) { data->final_unit_action = hdr->avp_value->i32; data->presence.final_unit_action=1; }
        else if (IS_AVP(davp_media_component_status)) { data->media_component_status = hdr->avp_value->u32; data->presence.media_component_status=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {
        FD_ALLOC_LIST(data->flow_number, uint32_t);
        FD_ALLOC_LIST(data->content_version, uint64_t);

        /* iterate through the Flows child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            if (IS_AVP(davp_flow_number)) { data->flow_number.list[data->flow_number.count] = hdr->avp_value->u32; data->flow_number.count++; }
            else if (IS_AVP(davp_content_version)) { data->content_version.list[data->content_version.count] = hdr->avp_value->u64; data->content_version.count++; }

            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*
*
*       Fun:    parseGxUserCsgInformation
*
*       Desc:   Parse User-CSG-Information AVP
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        User-CSG-Information ::= <AVP Header: 2319>
*              { CSG-Id }
*              { CSG-Access-Mode }
*              [ CSG-Membership-Indication ]
*/
static int parseGxUserCsgInformation
(
    struct avp *avp,
    GxUserCsgInformation *data
)
{
    int cnt = 0;
    struct avp_hdr *hdr;
    struct avp *child_avp = NULL;

    /* iterate through the User-CSG-Information child AVP's */
    FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

    /* keep going until there are no more child AVP's */
    while (child_avp)
    {
        fd_msg_avp_hdr (child_avp, &hdr);

        if (IS_AVP(davp_csg_id)) { data->csg_id = hdr->avp_value->u32; data->presence.csg_id=1; }
        else if (IS_AVP(davp_csg_access_mode)) { data->csg_access_mode = hdr->avp_value->i32; data->presence.csg_access_mode=1; }
        else if (IS_AVP(davp_csg_membership_indication)) { data->csg_membership_indication = hdr->avp_value->i32; data->presence.csg_membership_indication=1; }

         /* get the next child AVP */
        FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
    }

    /* process list AVP's if any are present */
    if (cnt > 0)
    {

        /* iterate through the User-CSG-Information child AVP's */
        FDCHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL), FD_REASON_BROWSE_FIRST_FAIL);

        /* keep going until there are no more child AVP's */
        while (child_avp)
        {
            fd_msg_avp_hdr (child_avp, &hdr);

            // There are no multiple occurance AVPs
            /* get the next child AVP */
            FDCHECK_FCT(fd_msg_browse(child_avp, MSG_BRW_NEXT, &child_avp, NULL), FD_REASON_BROWSE_NEXT_FAIL);
        }
    }

    return FD_REASON_OK;
}

/*******************************************************************************/
/* free structure data functions                                               */
/*******************************************************************************/

/*
*
*       Fun:    freeGxPraRemove
*
*       Desc:   Free the multiple occurrance AVP's for PRA-Remove
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        PRA-Remove ::= <AVP Header: 2846>
*          *   [ Presence-Reporting-Area-Identifier ]
*          *   [ AVP ]
*/
static int freeGxPraRemove
(
    GxPraRemove *data
)
{
    FD_FREE_LIST( data->presence_reporting_area_identifier );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxQosInformation
*
*       Desc:   Free the multiple occurrance AVP's for QoS-Information
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        QoS-Information ::= <AVP Header: 1016>
*              [ QoS-Class-Identifier ]
*              [ Max-Requested-Bandwidth-UL ]
*              [ Max-Requested-Bandwidth-DL ]
*              [ Extended-Max-Requested-BW-UL ]
*              [ Extended-Max-Requested-BW-DL ]
*              [ Guaranteed-Bitrate-UL ]
*              [ Guaranteed-Bitrate-DL ]
*              [ Extended-GBR-UL ]
*              [ Extended-GBR-DL ]
*              [ Bearer-Identifier ]
*              [ Allocation-Retention-Priority ]
*              [ APN-Aggregate-Max-Bitrate-UL ]
*              [ APN-Aggregate-Max-Bitrate-DL ]
*              [ Extended-APN-AMBR-UL ]
*              [ Extended-APN-AMBR-DL ]
*          *   [ Conditional-APN-Aggregate-Max-Bitrate ]
*          *   [ AVP ]
*/
static int freeGxQosInformation
(
    GxQosInformation *data
)
{
    FD_CALLFREE_LIST( data->conditional_apn_aggregate_max_bitrate, freeGxConditionalApnAggregateMaxBitrate );

    FD_FREE_LIST( data->conditional_apn_aggregate_max_bitrate );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxConditionalPolicyInformation
*
*       Desc:   Free the multiple occurrance AVP's for Conditional-Policy-Information
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Conditional-Policy-Information ::= <AVP Header: 2840>
*              [ Execution-Time ]
*              [ Default-EPS-Bearer-QoS ]
*              [ APN-Aggregate-Max-Bitrate-UL ]
*              [ APN-Aggregate-Max-Bitrate-DL ]
*              [ Extended-APN-AMBR-UL ]
*              [ Extended-APN-AMBR-DL ]
*          *   [ Conditional-APN-Aggregate-Max-Bitrate ]
*          *   [ AVP ]
*/
static int freeGxConditionalPolicyInformation
(
    GxConditionalPolicyInformation *data
)
{
    FD_CALLFREE_LIST( data->conditional_apn_aggregate_max_bitrate, freeGxConditionalApnAggregateMaxBitrate );

    FD_FREE_LIST( data->conditional_apn_aggregate_max_bitrate );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxPraInstall
*
*       Desc:   Free the multiple occurrance AVP's for PRA-Install
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        PRA-Install ::= <AVP Header: 2845>
*          *   [ Presence-Reporting-Area-Information ]
*          *   [ AVP ]
*/
static int freeGxPraInstall
(
    GxPraInstall *data
)
{
    FD_FREE_LIST( data->presence_reporting_area_information );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxAreaScope
*
*       Desc:   Free the multiple occurrance AVP's for Area-Scope
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Area-Scope ::= <AVP Header: 1624>
*          *   [ Cell-Global-Identity ]
*          *   [ E-UTRAN-Cell-Global-Identity ]
*          *   [ Routing-Area-Identity ]
*          *   [ Location-Area-Identity ]
*          *   [ Tracking-Area-Identity ]
*          *   [ AVP ]
*/
static int freeGxAreaScope
(
    GxAreaScope *data
)
{
    FD_FREE_LIST( data->cell_global_identity );
    FD_FREE_LIST( data->e_utran_cell_global_identity );
    FD_FREE_LIST( data->routing_area_identity );
    FD_FREE_LIST( data->location_area_identity );
    FD_FREE_LIST( data->tracking_area_identity );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxTunnelInformation
*
*       Desc:   Free the multiple occurrance AVP's for Tunnel-Information
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Tunnel-Information ::= <AVP Header: 1038>
*              [ Tunnel-Header-Length ]
*              [ Tunnel-Header-Filter ]
*/
static int freeGxTunnelInformation
(
    GxTunnelInformation *data
)
{
    FD_FREE_LIST( data->tunnel_header_filter );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxEventReportIndication
*
*       Desc:   Free the multiple occurrance AVP's for Event-Report-Indication
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Event-Report-Indication ::= <AVP Header: 1033>
*              [ AN-Trusted ]
*          *   [ Event-Trigger ]
*              [ User-CSG-Information ]
*              [ IP-CAN-Type ]
*          * 2 [ AN-GW-Address ]
*              [ 3GPP-SGSN-Address ]
*              [ 3GPP-SGSN-Ipv6-Address ]
*              [ 3GPP-SGSN-MCC-MNC ]
*              [ Framed-IP-Address ]
*              [ RAT-Type ]
*              [ RAI ]
*              [ 3GPP-User-Location-Info ]
*              [ Trace-Data ]
*              [ Trace-Reference ]
*              [ 3GPP2-BSID ]
*              [ 3GPP-MS-TimeZone ]
*              [ Routing-IP-Address ]
*              [ UE-Local-IP-Address ]
*              [ HeNB-Local-IP-Address ]
*              [ UDP-Source-Port ]
*              [ Presence-Reporting-Area-Information ]
*          *   [ AVP ]
*/
static int freeGxEventReportIndication
(
    GxEventReportIndication *data
)
{
    FD_CALLFREE_STRUCT( data->trace_data, freeGxTraceData );

    FD_FREE_LIST( data->event_trigger );
    FD_FREE_LIST( data->an_gw_address );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxUsedServiceUnit
*
*       Desc:   Free the multiple occurrance AVP's for Used-Service-Unit
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Used-Service-Unit ::= <AVP Header: 446>
*              [ Reporting-Reason ]
*              [ Tariff-Change-Usage ]
*              [ CC-Time ]
*              [ CC-Money ]
*              [ CC-Total-Octets ]
*              [ CC-Input-Octets ]
*              [ CC-Output-Octets ]
*              [ CC-Service-Specific-Units ]
*          *   [ Event-Charging-TimeStamp ]
*          *   [ AVP ]
*/
static int freeGxUsedServiceUnit
(
    GxUsedServiceUnit *data
)
{
    FD_FREE_LIST( data->event_charging_timestamp );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxChargingRuleInstall
*
*       Desc:   Free the multiple occurrance AVP's for Charging-Rule-Install
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Charging-Rule-Install ::= <AVP Header: 1001>
*          *   [ Charging-Rule-Definition ]
*          *   [ Charging-Rule-Name ]
*          *   [ Charging-Rule-Base-Name ]
*              [ Bearer-Identifier ]
*              [ Monitoring-Flags ]
*              [ Rule-Activation-Time ]
*              [ Rule-Deactivation-Time ]
*              [ Resource-Allocation-Notification ]
*              [ Charging-Correlation-Indicator ]
*              [ IP-CAN-Type ]
*          *   [ AVP ]
*/
static int freeGxChargingRuleInstall
(
    GxChargingRuleInstall *data
)
{
    FD_CALLFREE_LIST( data->charging_rule_definition, freeGxChargingRuleDefinition );

    FD_FREE_LIST( data->charging_rule_definition );
    FD_FREE_LIST( data->charging_rule_name );
    FD_FREE_LIST( data->charging_rule_base_name );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxChargingRuleDefinition
*
*       Desc:   Free the multiple occurrance AVP's for Charging-Rule-Definition
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Charging-Rule-Definition ::= <AVP Header: 1003>
*              { Charging-Rule-Name }
*              [ Service-Identifier ]
*              [ Rating-Group ]
*          *   [ Flow-Information ]
*              [ Default-Bearer-Indication ]
*              [ TDF-Application-Identifier ]
*              [ Flow-Status ]
*              [ QoS-Information ]
*              [ PS-to-CS-Session-Continuity ]
*              [ Reporting-Level ]
*              [ Online ]
*              [ Offline ]
*              [ Max-PLR-DL ]
*              [ Max-PLR-UL ]
*              [ Metering-Method ]
*              [ Precedence ]
*              [ AF-Charging-Identifier ]
*          *   [ Flows ]
*              [ Monitoring-Key ]
*              [ Redirect-Information ]
*              [ Mute-Notification ]
*              [ AF-Signalling-Protocol ]
*              [ Sponsor-Identity ]
*              [ Application-Service-Provider-Identity ]
*          *   [ Required-Access-Info ]
*              [ Sharing-Key-DL ]
*              [ Sharing-Key-UL ]
*              [ Traffic-Steering-Policy-Identifier-DL ]
*              [ Traffic-Steering-Policy-Identifier-UL ]
*              [ Content-Version ]
*          *   [ AVP ]
*/
static int freeGxChargingRuleDefinition
(
    GxChargingRuleDefinition *data
)
{
    FD_CALLFREE_STRUCT( data->qos_information, freeGxQosInformation );
    FD_CALLFREE_LIST( data->flows, freeGxFlows );

    FD_FREE_LIST( data->flow_information );
    FD_FREE_LIST( data->flows );
    FD_FREE_LIST( data->required_access_info );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxFinalUnitIndication
*
*       Desc:   Free the multiple occurrance AVP's for Final-Unit-Indication
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Final-Unit-Indication ::= <AVP Header: 430>
*              { Final-Unit-Action }
*          *   [ Restriction-Filter-Rule ]
*          *   [ Filter-Id ]
*              [ Redirect-Server ]
*/
static int freeGxFinalUnitIndication
(
    GxFinalUnitIndication *data
)
{
    FD_FREE_LIST( data->restriction_filter_rule );
    FD_FREE_LIST( data->filter_id );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxConditionalApnAggregateMaxBitrate
*
*       Desc:   Free the multiple occurrance AVP's for Conditional-APN-Aggregate-Max-Bitrate
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Conditional-APN-Aggregate-Max-Bitrate ::= <AVP Header: 2818>
*              [ APN-Aggregate-Max-Bitrate-UL ]
*              [ APN-Aggregate-Max-Bitrate-DL ]
*              [ Extended-APN-AMBR-UL ]
*              [ Extended-APN-AMBR-DL ]
*          *   [ IP-CAN-Type ]
*          *   [ RAT-Type ]
*          *   [ AVP ]
*/
static int freeGxConditionalApnAggregateMaxBitrate
(
    GxConditionalApnAggregateMaxBitrate *data
)
{
    FD_FREE_LIST( data->ip_can_type );
    FD_FREE_LIST( data->rat_type );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxAccessNetworkChargingIdentifierGx
*
*       Desc:   Free the multiple occurrance AVP's for Access-Network-Charging-Identifier-Gx
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Access-Network-Charging-Identifier-Gx ::= <AVP Header: 1022>
*              { Access-Network-Charging-Identifier-Value }
*          *   [ Charging-Rule-Base-Name ]
*          *   [ Charging-Rule-Name ]
*              [ IP-CAN-Session-Charging-Scope ]
*          *   [ AVP ]
*/
static int freeGxAccessNetworkChargingIdentifierGx
(
    GxAccessNetworkChargingIdentifierGx *data
)
{
    FD_FREE_LIST( data->charging_rule_base_name );
    FD_FREE_LIST( data->charging_rule_name );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxRoutingRuleInstall
*
*       Desc:   Free the multiple occurrance AVP's for Routing-Rule-Install
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Routing-Rule-Install ::= <AVP Header: 1081>
*          *   [ Routing-Rule-Definition ]
*          *   [ AVP ]
*/
static int freeGxRoutingRuleInstall
(
    GxRoutingRuleInstall *data
)
{
    FD_CALLFREE_LIST( data->routing_rule_definition, freeGxRoutingRuleDefinition );

    FD_FREE_LIST( data->routing_rule_definition );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxTraceData
*
*       Desc:   Free the multiple occurrance AVP's for Trace-Data
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Trace-Data ::= <AVP Header: 1458>
*              { Trace-Reference }
*              { Trace-Depth }
*              { Trace-NE-Type-List }
*              [ Trace-Interface-List ]
*              { Trace-Event-List }
*              [ OMC-Id ]
*              { Trace-Collection-Entity }
*              [ MDT-Configuration ]
*          *   [ AVP ]
*/
static int freeGxTraceData
(
    GxTraceData *data
)
{
    FD_CALLFREE_STRUCT( data->mdt_configuration, freeGxMdtConfiguration );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxRoutingRuleDefinition
*
*       Desc:   Free the multiple occurrance AVP's for Routing-Rule-Definition
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Routing-Rule-Definition ::= <AVP Header: 1076>
*              { Routing-Rule-Identifier }
*          *   [ Routing-Filter ]
*              [ Precedence ]
*              [ Routing-IP-Address ]
*              [ IP-CAN-Type ]
*          *   [ AVP ]
*/
static int freeGxRoutingRuleDefinition
(
    GxRoutingRuleDefinition *data
)
{
    FD_FREE_LIST( data->routing_filter );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxMdtConfiguration
*
*       Desc:   Free the multiple occurrance AVP's for MDT-Configuration
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        MDT-Configuration ::= <AVP Header: 1622>
*              { Job-Type }
*              [ Area-Scope ]
*              [ List-Of-Measurements ]
*              [ Reporting-Trigger ]
*              [ Report-Interval ]
*              [ Report-Amount ]
*              [ Event-Threshold-RSRP ]
*              [ Event-Threshold-RSRQ ]
*              [ Logging-Interval ]
*              [ Logging-Duration ]
*              [ Measurement-Period-LTE ]
*              [ Measurement-Period-UMTS ]
*              [ Collection-Period-RRM-LTE ]
*              [ Collection-Period-RRM-UMTS ]
*              [ Positioning-Method ]
*              [ Measurement-Quantity ]
*              [ Event-Threshold-Event-1F ]
*              [ Event-Threshold-Event-1I ]
*          *   [ MDT-Allowed-PLMN-Id ]
*          *   [ MBSFN-Area ]
*          *   [ AVP ]
*/
static int freeGxMdtConfiguration
(
    GxMdtConfiguration *data
)
{
    FD_CALLFREE_STRUCT( data->area_scope, freeGxAreaScope );

    FD_FREE_LIST( data->mdt_allowed_plmn_id );
    FD_FREE_LIST( data->mbsfn_area );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxChargingRuleRemove
*
*       Desc:   Free the multiple occurrance AVP's for Charging-Rule-Remove
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Charging-Rule-Remove ::= <AVP Header: 1002>
*          *   [ Charging-Rule-Name ]
*          *   [ Charging-Rule-Base-Name ]
*          *   [ Required-Access-Info ]
*              [ Resource-Release-Notification ]
*          *   [ AVP ]
*/
static int freeGxChargingRuleRemove
(
    GxChargingRuleRemove *data
)
{
    FD_FREE_LIST( data->charging_rule_name );
    FD_FREE_LIST( data->charging_rule_base_name );
    FD_FREE_LIST( data->required_access_info );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxRoutingRuleReport
*
*       Desc:   Free the multiple occurrance AVP's for Routing-Rule-Report
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Routing-Rule-Report ::= <AVP Header: 2835>
*          *   [ Routing-Rule-Identifier ]
*              [ PCC-Rule-Status ]
*              [ Routing-Rule-Failure-Code ]
*          *   [ AVP ]
*/
static int freeGxRoutingRuleReport
(
    GxRoutingRuleReport *data
)
{
    FD_FREE_LIST( data->routing_rule_identifier );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxUsageMonitoringInformation
*
*       Desc:   Free the multiple occurrance AVP's for Usage-Monitoring-Information
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Usage-Monitoring-Information ::= <AVP Header: 1067>
*              [ Monitoring-Key ]
*          * 2 [ Granted-Service-Unit ]
*          * 2 [ Used-Service-Unit ]
*              [ Quota-Consumption-Time ]
*              [ Usage-Monitoring-Level ]
*              [ Usage-Monitoring-Report ]
*              [ Usage-Monitoring-Support ]
*          *   [ AVP ]
*/
static int freeGxUsageMonitoringInformation
(
    GxUsageMonitoringInformation *data
)
{
    FD_CALLFREE_LIST( data->used_service_unit, freeGxUsedServiceUnit );

    FD_FREE_LIST( data->granted_service_unit );
    FD_FREE_LIST( data->used_service_unit );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxChargingRuleReport
*
*       Desc:   Free the multiple occurrance AVP's for Charging-Rule-Report
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Charging-Rule-Report ::= <AVP Header: 1018>
*          *   [ Charging-Rule-Name ]
*          *   [ Charging-Rule-Base-Name ]
*              [ Bearer-Identifier ]
*              [ PCC-Rule-Status ]
*              [ Rule-Failure-Code ]
*              [ Final-Unit-Indication ]
*          *   [ RAN-NAS-Release-Cause ]
*          *   [ Content-Version ]
*          *   [ AVP ]
*/
static int freeGxChargingRuleReport
(
    GxChargingRuleReport *data
)
{
    FD_CALLFREE_STRUCT( data->final_unit_indication, freeGxFinalUnitIndication );

    FD_FREE_LIST( data->charging_rule_name );
    FD_FREE_LIST( data->charging_rule_base_name );
    FD_FREE_LIST( data->ran_nas_release_cause );
    FD_FREE_LIST( data->content_version );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxRoutingRuleRemove
*
*       Desc:   Free the multiple occurrance AVP's for Routing-Rule-Remove
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Routing-Rule-Remove ::= <AVP Header: 1075>
*          *   [ Routing-Rule-Identifier ]
*          *   [ AVP ]
*/
static int freeGxRoutingRuleRemove
(
    GxRoutingRuleRemove *data
)
{
    FD_FREE_LIST( data->routing_rule_identifier );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxCoaInformation
*
*       Desc:   Free the multiple occurrance AVP's for CoA-Information
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        CoA-Information ::= <AVP Header: 1039>
*              { Tunnel-Information }
*              { CoA-IP-Address }
*          *   [ AVP ]
*/
static int freeGxCoaInformation
(
    GxCoaInformation *data
)
{
    FD_CALLFREE_STRUCT( data->tunnel_information, freeGxTunnelInformation );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxApplicationDetectionInformation
*
*       Desc:   Free the multiple occurrance AVP's for Application-Detection-Information
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Application-Detection-Information ::= <AVP Header: 1098>
*              { TDF-Application-Identifier }
*              [ TDF-Application-Instance-Identifier ]
*          *   [ Flow-Information ]
*          *   [ AVP ]
*/
static int freeGxApplicationDetectionInformation
(
    GxApplicationDetectionInformation *data
)
{
    FD_FREE_LIST( data->flow_information );

    return FD_REASON_OK;
}

/*
*
*       Fun:    freeGxFlows
*
*       Desc:   Free the multiple occurrance AVP's for Flows
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_parsers.c
*
*
*
*        Flows ::= <AVP Header: 510>
*              { Media-Component-Number }
*          *   [ Flow-Number ]
*          *   [ Content-Version ]
*              [ Final-Unit-Action ]
*              [ Media-Component-Status ]
*          *   [ AVP ]
*/
static int freeGxFlows
(
    GxFlows *data
)
{
    FD_FREE_LIST( data->flow_number );
    FD_FREE_LIST( data->content_version );

    return FD_REASON_OK;
}

