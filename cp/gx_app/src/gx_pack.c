#include <stdint.h>
#include <stdlib.h>

#include "gx.h"

#define MIN(a,b) (((a) < (b)) ? (a) : (b))

/*******************************************************************************/

#define CALCLEN_PRESENCE(__length__,__data__,__member__) {  \
   __length__ += sizeof(__data__->__member__);              \
}

#define CALCLEN_BASIC(__length__,__data__,__member__) {  \
   if (__data__->presence.__member__)                    \
      __length__ += sizeof(__data__->__member__);        \
}

#define CALCLEN_OCTETSTRING(__length__,__data__,__member__) {     \
   if (__data__->presence.__member__)                             \
      __length__ += sizeof(uint32_t) + __data__->__member__.len;  \
}

#define CALCLEN_STRUCT(__length__,__data__,__member__,__calcfunc__) {   \
   if (__data__->presence.__member__)                                   \
      __length__ += __calcfunc__( &__data__->__member__ );              \
}

#define CALCLEN_LIST_BASIC(__length__,__data__,__member__) {                                             \
   if (__data__->presence.__member__) {                                                                  \
      __length__ += sizeof(int32_t) + sizeof(*__data__->__member__.list) * __data__->__member__.count;   \
   }                                                                                                     \
}

#define CALCLEN_LIST_OCTETSTRING(__length__,__data__,__member__) {            \
   if (__data__->presence.__member__) {                                       \
      __length__ += sizeof(int32_t);                                          \
      for (int32_t idx=0; idx<__data__->__member__.count; idx++) {            \
         __length__ += sizeof(uint32_t) + __data__->__member__.list[idx].len; \
      }                                                                       \
   }                                                                          \
}

#define CALCLEN_LIST_STRUCT(__length__,__data__,__member__,__calcfunc__) { \
   if (__data__->presence.__member__) {                                    \
      __length__ += sizeof(int32_t);                                       \
      for (int32_t idx=0; idx<__data__->__member__.count; idx++)           \
         __length__ += __calcfunc__( &__data__->__member__.list[idx] );    \
   }                                                                       \
}

/*******************************************************************************/

#define PACK_PRESENCE(__data__,__member__,__buffer__,__buflen__,__offset__) {                                  \
   if (*__offset__ + sizeof(__data__->__member__) > __buflen__)                                                \
      return 0;                                                                                                \
   memcpy( &__buffer__[*__offset__], (unsigned char *)&(__data__->__member__), sizeof(__data__->__member__));  \
   *__offset__ += sizeof(__data__->__member__);                                                                \
}

#define PACK_BASIC(__data__,__member__,__buffer__,__buflen__,__offset__) {                                        \
   if (__data__->presence.__member__) {                                                                           \
      if (*__offset__ + sizeof(__data__->__member__) > __buflen__)                                                \
         return 0;                                                                                                \
      memcpy( &__buffer__[*__offset__], (unsigned char *)&(__data__->__member__), sizeof(__data__->__member__));  \
      *__offset__ += sizeof(__data__->__member__);                                                                \
   }                                                                                                              \
}

#define PACK_OCTETSTRING(__data__,__member__,__buffer__,__buflen__,__offset__) {                               \
   if (__data__->presence.__member__) {                                                                        \
      if (*__offset__ + sizeof(uint32_t) + __data__->__member__.len > __buflen__)                              \
         return 0;                                                                                             \
      *((uint32_t*)&__buffer__[*__offset__]) = __data__->__member__.len;                                       \
      *__offset__ += sizeof(uint32_t);                                                                         \
      memcpy( &__buffer__[*__offset__], (unsigned char *)__data__->__member__.val, __data__->__member__.len ); \
      *__offset__ += __data__->__member__.len;                                                                 \
   }                                                                                                           \
}

#define PACK_STRUCT(__data__,__member__,__buffer__,__buflen__,__offset__,__packfunc__) {  \
   if (__data__->presence.__member__) {                                                   \
      if (!__packfunc__(&__data__->__member__,__buffer__,__buflen__,__offset__))          \
         return 0;                                                                        \
   }                                                                                      \
}

#define PACK_LIST_BASIC(__data__,__member__,__buffer__,__buflen__,__offset__) {                                                     \
   if (__data__->presence.__member__) {                                                                                             \
      if (*__offset__ + sizeof(int32_t) > __buflen__)                                                                               \
         return 0;                                                                                                                  \
      *(int32_t*)&__buffer__[*__offset__] = __data__->__member__.count;                                                             \
      *__offset__ += sizeof(int32_t);                                                                                               \
      for (int32_t idx=0; idx<__data__->__member__.count; idx++) {                                                                  \
         if ((*__offset__ + sizeof(*__data__->__member__.list)) > __buflen__)                                                       \
            return 0;                                                                                                               \
         memcpy( &__buffer__[*__offset__], (unsigned char *)&__data__->__member__.list[idx], sizeof(*__data__->__member__.list) );  \
         *__offset__ += sizeof(*__data__->__member__.list);                                                                         \
      }                                                                                                                             \
   }                                                                                                                                \
}

#define PACK_LIST_OCTETSTRING(__data__,__member__,__buffer__,__buflen__,__offset__) {                                                  \
   if (__data__->presence.__member__) {                                                                                                \
      if ((*__offset__ + sizeof(int32_t)) > __buflen__)                                                                                \
         return 0;                                                                                                                     \
      *(int32_t*)(&__buffer__[*__offset__]) = __data__->__member__.count;                                                              \
      *__offset__ += sizeof(int32_t);                                                                                                  \
      for (int32_t idx=0; idx<__data__->__member__.count; idx++) {                                                                     \
         if ((*__offset__ + sizeof(uint32_t) + __data__->__member__.list[idx].len) > __buflen__)                                       \
            return 0;                                                                                                                  \
         *(uint32_t*)&__buffer__[*__offset__] += __data__->__member__.list[idx].len;                                                   \
         *__offset__ += sizeof(uint32_t);                                                                                              \
         memcpy( &__buffer__[*__offset__], (unsigned char *)&__data__->__member__.list[idx].val, __data__->__member__.list[idx].len);  \
         *__offset__ += __data__->__member__.list[idx].len;                                                                            \
      }                                                                                                                                \
   }                                                                                                                                   \
}

#define PACK_LIST_STRUCT(__data__,__member__,__buffer__,__buflen__,__offset__,__packfunc__) {   \
   if (__data__->presence.__member__) {                                                         \
      if ((*__offset__ + sizeof(int32_t)) > __buflen__)                                         \
         return 0;                                                                              \
      *(int32_t*)(&__buffer__[*__offset__]) = __data__->__member__.count;                       \
      *__offset__ += sizeof(int32_t);                                                           \
      for (int32_t idx=0; idx<__data__->__member__.count; idx++) {                              \
         if (!__packfunc__(&__data__->__member__.list[idx],__buffer__,__buflen__,__offset__))   \
            return 0;                                                                           \
      }                                                                                         \
   }                                                                                            \
}

/*******************************************************************************/

#define UNPACK_PRESENCE(__data__,__member__,__buffer__,__buflen__,__offset__) {                             \
   if (*__offset__ + sizeof(__data__->__member__) > __buflen__)                                             \
      return 0;                                                                                             \
   memcpy((unsigned char *)&__data__->__member__, &__buffer__[*__offset__], sizeof(__data__->__member__));  \
   *__offset__ += sizeof(__data__->__member__);                                                             \
}

#define UNPACK_BASIC(__data__,__member__,__buffer__,__buflen__,__offset__) {                                   \
   if (__data__->presence.__member__) {                                                                        \
      if (*__offset__ + sizeof(__data__->__member__) > __buflen__)                                             \
         return 0;                                                                                             \
      memcpy((unsigned char *)&__data__->__member__, &__buffer__[*__offset__], sizeof(__data__->__member__));  \
      *__offset__ += sizeof(__data__->__member__);                                                             \
   }                                                                                                           \
}

#define UNPACK_OCTETSTRING(__data__,__member__,__buffer__,__buflen__,__offset__) {           \
   if (__data__->presence.__member__) {                                                      \
      if (*__offset__ + sizeof(uint32_t) > __buflen__)                                       \
         return 0;                                                                           \
      uint32_t __len__ = *((uint32_t*)&__buffer__[*__offset__]);                             \
      __data__->__member__.len = MIN(__len__, sizeof(__data__->__member__.val) - 1);         \
      *__offset__ += sizeof(uint32_t);                                                       \
      if (*__offset__ + __len__ > __buflen__)                                                \
         return 0;                                                                           \
      memcpy(__data__->__member__.val, &__buffer__[*__offset__], __data__->__member__.len);  \
      __data__->__member__.val[__data__->__member__.len] = '\0';                             \
      *__offset__ += __len__;                                                                \
   }                                                                                         \
}

#define UNPACK_STRUCT(__data__,__member__,__buffer__,__buflen__,__offset__,__unpackfunc__) {    \
   if (__data__->presence.__member__) {                                                         \
      if (!__unpackfunc__(__buffer__,__buflen__,&__data__->__member__,__offset__))              \
         return 0;                                                                              \
   }                                                                                            \
}

#define UNPACK_LIST_BASIC(__data__,__member__,__listtype__,__buffer__,__buflen__,__offset__) {                                         \
   if (__data__->presence.__member__) {                                                                                                \
      if (*__offset__ + sizeof(int32_t) > __buflen__)                                                                                  \
         return 0;                                                                                                                     \
      __data__->__member__.count = *(int32_t*)&__buffer__[*__offset__];                                                                \
      *__offset__ += sizeof(int32_t);                                                                                                  \
      __data__->__member__.list = (__listtype__*)malloc(sizeof(__listtype__) * __data__->__member__.count);                            \
      if (!__data__->__member__.list)                                                                                                  \
         return 0;                                                                                                                     \
      for (int32_t idx=0; idx<__data__->__member__.count; idx++) {                                                                     \
         if (*__offset__ + sizeof(__data__->__member__.list[idx]) > __buflen__)                                                        \
            return 0;                                                                                                                  \
         memcpy((unsigned char *)&__data__->__member__.list[idx], &__buffer__[*__offset__], sizeof(__data__->__member__.list[idx]));   \
         *__offset__ += sizeof(__data__->__member__.list[idx]);                                                                        \
      }                                                                                                                                \
   }                                                                                                                                   \
}

#define UNPACK_LIST_OCTETSTRING(__data__,__member__,__listtype__,__buffer__,__buflen__,__offset__) {                 \
   if (__data__->presence.__member__) {                                                                              \
      if ((*__offset__ + sizeof(int32_t)) >=__buflen__)                                                              \
         return 0;                                                                                                   \
      __data__->__member__.count = *(int32_t*)&__buffer__[*__offset__];                                              \
      *__offset__ += sizeof(int32_t);                                                                                \
      __data__->__member__.list = (__listtype__*)malloc(sizeof(__listtype__) * __data__->__member__.count);          \
      if (!__data__->__member__.list)                                                                                \
         return 0;                                                                                                   \
      for (int32_t idx=0; idx <__data__->__member__.count; idx++) {                                                  \
         if (*__offset__ + sizeof(uint32_t) > __buflen__)                                                            \
            return 0;                                                                                                \
         uint32_t __len__ =  *(uint32_t*)&__buffer__[*__offset__];                                                   \
         *__offset__ += sizeof(uint32_t);                                                                            \
         __data__->__member__.list[idx].len = MIN(__len__, sizeof(__data__->__member__.list[idx].val) - 1);          \
         memcpy(__data__->__member__.list[idx].val, &__buffer__[*__offset__], __data__->__member__.list[idx].len);   \
         *__offset__ += __len__;                                                                                     \
      }                                                                                                              \
   }                                                                                                                 \
}

#define UNPACK_LIST_STRUCT(__data__,__member__,__listtype__,__buffer__,__buflen__,__offset__,__unpackfunc__) { \
   if (__data__->presence.__member__) {                                                                        \
      if (*__offset__ + sizeof(int32_t) > __buflen__)                                                          \
         return 0;                                                                                             \
      __data__->__member__.count = *(int32_t*)&__buffer__[*__offset__];                                        \
      *__offset__ += sizeof(int32_t);                                                                          \
      __data__->__member__.list = (__listtype__*)malloc(sizeof(__listtype__) * __data__->__member__.count);    \
      if (!__data__->__member__.list)                                                                          \
         return 0;                                                                                             \
      for (int32_t idx=0; idx<__data__->__member__.count; idx++) {                                             \
         if (!__unpackfunc__(__buffer__,__buflen__,&__data__->__member__.list[idx],__offset__))                \
            return 0;                                                                                          \
      }                                                                                                        \
   }                                                                                                           \
}

/*******************************************************************************/
/* private structure calc_length, pack and unpack function declarations        */
/*******************************************************************************/

static uint32_t calcLengthGxExperimentalResult(GxExperimentalResult *data);
static uint32_t calcLengthGxPraRemove(GxPraRemove *data);
static uint32_t calcLengthGxQosInformation(GxQosInformation *data);
static uint32_t calcLengthGxConditionalPolicyInformation(GxConditionalPolicyInformation *data);
static uint32_t calcLengthGxPraInstall(GxPraInstall *data);
static uint32_t calcLengthGxAreaScope(GxAreaScope *data);
static uint32_t calcLengthGxFlowInformation(GxFlowInformation *data);
static uint32_t calcLengthGxTunnelInformation(GxTunnelInformation *data);
static uint32_t calcLengthGxTftPacketFilterInformation(GxTftPacketFilterInformation *data);
static uint32_t calcLengthGxMbsfnArea(GxMbsfnArea *data);
static uint32_t calcLengthGxEventReportIndication(GxEventReportIndication *data);
static uint32_t calcLengthGxTdfInformation(GxTdfInformation *data);
static uint32_t calcLengthGxProxyInfo(GxProxyInfo *data);
static uint32_t calcLengthGxUsedServiceUnit(GxUsedServiceUnit *data);
static uint32_t calcLengthGxChargingRuleInstall(GxChargingRuleInstall *data);
static uint32_t calcLengthGxChargingRuleDefinition(GxChargingRuleDefinition *data);
static uint32_t calcLengthGxFinalUnitIndication(GxFinalUnitIndication *data);
static uint32_t calcLengthGxUnitValue(GxUnitValue *data);
static uint32_t calcLengthGxPresenceReportingAreaInformation(GxPresenceReportingAreaInformation *data);
static uint32_t calcLengthGxConditionalApnAggregateMaxBitrate(GxConditionalApnAggregateMaxBitrate *data);
static uint32_t calcLengthGxAccessNetworkChargingIdentifierGx(GxAccessNetworkChargingIdentifierGx *data);
static uint32_t calcLengthGxOcOlr(GxOcOlr *data);
static uint32_t calcLengthGxRoutingRuleInstall(GxRoutingRuleInstall *data);
static uint32_t calcLengthGxTraceData(GxTraceData *data);
static uint32_t calcLengthGxRoutingRuleDefinition(GxRoutingRuleDefinition *data);
static uint32_t calcLengthGxMdtConfiguration(GxMdtConfiguration *data);
static uint32_t calcLengthGxChargingRuleRemove(GxChargingRuleRemove *data);
static uint32_t calcLengthGxAllocationRetentionPriority(GxAllocationRetentionPriority *data);
static uint32_t calcLengthGxDefaultEpsBearerQos(GxDefaultEpsBearerQos *data);
static uint32_t calcLengthGxRoutingRuleReport(GxRoutingRuleReport *data);
static uint32_t calcLengthGxUserEquipmentInfo(GxUserEquipmentInfo *data);
static uint32_t calcLengthGxSupportedFeatures(GxSupportedFeatures *data);
static uint32_t calcLengthGxFixedUserLocationInfo(GxFixedUserLocationInfo *data);
static uint32_t calcLengthGxDefaultQosInformation(GxDefaultQosInformation *data);
static uint32_t calcLengthGxLoad(GxLoad *data);
static uint32_t calcLengthGxRedirectServer(GxRedirectServer *data);
static uint32_t calcLengthGxOcSupportedFeatures(GxOcSupportedFeatures *data);
static uint32_t calcLengthGxPacketFilterInformation(GxPacketFilterInformation *data);
static uint32_t calcLengthGxSubscriptionId(GxSubscriptionId *data);
static uint32_t calcLengthGxChargingInformation(GxChargingInformation *data);
static uint32_t calcLengthGxUsageMonitoringInformation(GxUsageMonitoringInformation *data);
static uint32_t calcLengthGxChargingRuleReport(GxChargingRuleReport *data);
static uint32_t calcLengthGxRedirectInformation(GxRedirectInformation *data);
static uint32_t calcLengthGxFailedAvp(GxFailedAvp *data);
static uint32_t calcLengthGxRoutingRuleRemove(GxRoutingRuleRemove *data);
static uint32_t calcLengthGxRoutingFilter(GxRoutingFilter *data);
static uint32_t calcLengthGxCoaInformation(GxCoaInformation *data);
static uint32_t calcLengthGxGrantedServiceUnit(GxGrantedServiceUnit *data);
static uint32_t calcLengthGxCcMoney(GxCcMoney *data);
static uint32_t calcLengthGxApplicationDetectionInformation(GxApplicationDetectionInformation *data);
static uint32_t calcLengthGxFlows(GxFlows *data);
static uint32_t calcLengthGxUserCsgInformation(GxUserCsgInformation *data);

static int packGxExperimentalResult(GxExperimentalResult *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxPraRemove(GxPraRemove *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxQosInformation(GxQosInformation *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxConditionalPolicyInformation(GxConditionalPolicyInformation *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxPraInstall(GxPraInstall *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxAreaScope(GxAreaScope *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxFlowInformation(GxFlowInformation *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxTunnelInformation(GxTunnelInformation *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxTftPacketFilterInformation(GxTftPacketFilterInformation *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxMbsfnArea(GxMbsfnArea *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxEventReportIndication(GxEventReportIndication *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxTdfInformation(GxTdfInformation *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxProxyInfo(GxProxyInfo *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxUsedServiceUnit(GxUsedServiceUnit *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxChargingRuleInstall(GxChargingRuleInstall *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxChargingRuleDefinition(GxChargingRuleDefinition *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxFinalUnitIndication(GxFinalUnitIndication *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxUnitValue(GxUnitValue *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxPresenceReportingAreaInformation(GxPresenceReportingAreaInformation *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxConditionalApnAggregateMaxBitrate(GxConditionalApnAggregateMaxBitrate *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxAccessNetworkChargingIdentifierGx(GxAccessNetworkChargingIdentifierGx *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxOcOlr(GxOcOlr *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxRoutingRuleInstall(GxRoutingRuleInstall *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxTraceData(GxTraceData *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxRoutingRuleDefinition(GxRoutingRuleDefinition *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxMdtConfiguration(GxMdtConfiguration *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxChargingRuleRemove(GxChargingRuleRemove *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxAllocationRetentionPriority(GxAllocationRetentionPriority *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxDefaultEpsBearerQos(GxDefaultEpsBearerQos *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxRoutingRuleReport(GxRoutingRuleReport *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxUserEquipmentInfo(GxUserEquipmentInfo *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxSupportedFeatures(GxSupportedFeatures *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxFixedUserLocationInfo(GxFixedUserLocationInfo *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxDefaultQosInformation(GxDefaultQosInformation *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxLoad(GxLoad *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxRedirectServer(GxRedirectServer *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxOcSupportedFeatures(GxOcSupportedFeatures *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxPacketFilterInformation(GxPacketFilterInformation *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxSubscriptionId(GxSubscriptionId *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxChargingInformation(GxChargingInformation *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxUsageMonitoringInformation(GxUsageMonitoringInformation *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxChargingRuleReport(GxChargingRuleReport *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxRedirectInformation(GxRedirectInformation *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxFailedAvp(GxFailedAvp *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxRoutingRuleRemove(GxRoutingRuleRemove *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxRoutingFilter(GxRoutingFilter *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxCoaInformation(GxCoaInformation *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxGrantedServiceUnit(GxGrantedServiceUnit *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxCcMoney(GxCcMoney *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxApplicationDetectionInformation(GxApplicationDetectionInformation *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxFlows(GxFlows *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);
static int packGxUserCsgInformation(GxUserCsgInformation *data, unsigned char *buf, uint32_t buflen, uint32_t *offset);

static int unpackGxExperimentalResult(unsigned char *buf, uint32_t buflen, GxExperimentalResult *data, uint32_t *offset);
static int unpackGxPraRemove(unsigned char *buf, uint32_t buflen, GxPraRemove *data, uint32_t *offset);
static int unpackGxQosInformation(unsigned char *buf, uint32_t buflen, GxQosInformation *data, uint32_t *offset);
static int unpackGxConditionalPolicyInformation(unsigned char *buf, uint32_t buflen, GxConditionalPolicyInformation *data, uint32_t *offset);
static int unpackGxPraInstall(unsigned char *buf, uint32_t buflen, GxPraInstall *data, uint32_t *offset);
static int unpackGxAreaScope(unsigned char *buf, uint32_t buflen, GxAreaScope *data, uint32_t *offset);
static int unpackGxFlowInformation(unsigned char *buf, uint32_t buflen, GxFlowInformation *data, uint32_t *offset);
static int unpackGxTunnelInformation(unsigned char *buf, uint32_t buflen, GxTunnelInformation *data, uint32_t *offset);
static int unpackGxTftPacketFilterInformation(unsigned char *buf, uint32_t buflen, GxTftPacketFilterInformation *data, uint32_t *offset);
static int unpackGxMbsfnArea(unsigned char *buf, uint32_t buflen, GxMbsfnArea *data, uint32_t *offset);
static int unpackGxEventReportIndication(unsigned char *buf, uint32_t buflen, GxEventReportIndication *data, uint32_t *offset);
static int unpackGxTdfInformation(unsigned char *buf, uint32_t buflen, GxTdfInformation *data, uint32_t *offset);
static int unpackGxProxyInfo(unsigned char *buf, uint32_t buflen, GxProxyInfo *data, uint32_t *offset);
static int unpackGxUsedServiceUnit(unsigned char *buf, uint32_t buflen, GxUsedServiceUnit *data, uint32_t *offset);
static int unpackGxChargingRuleInstall(unsigned char *buf, uint32_t buflen, GxChargingRuleInstall *data, uint32_t *offset);
static int unpackGxChargingRuleDefinition(unsigned char *buf, uint32_t buflen, GxChargingRuleDefinition *data, uint32_t *offset);
static int unpackGxFinalUnitIndication(unsigned char *buf, uint32_t buflen, GxFinalUnitIndication *data, uint32_t *offset);
static int unpackGxUnitValue(unsigned char *buf, uint32_t buflen, GxUnitValue *data, uint32_t *offset);
static int unpackGxPresenceReportingAreaInformation(unsigned char *buf, uint32_t buflen, GxPresenceReportingAreaInformation *data, uint32_t *offset);
static int unpackGxConditionalApnAggregateMaxBitrate(unsigned char *buf, uint32_t buflen, GxConditionalApnAggregateMaxBitrate *data, uint32_t *offset);
static int unpackGxAccessNetworkChargingIdentifierGx(unsigned char *buf, uint32_t buflen, GxAccessNetworkChargingIdentifierGx *data, uint32_t *offset);
static int unpackGxOcOlr(unsigned char *buf, uint32_t buflen, GxOcOlr *data, uint32_t *offset);
static int unpackGxRoutingRuleInstall(unsigned char *buf, uint32_t buflen, GxRoutingRuleInstall *data, uint32_t *offset);
static int unpackGxTraceData(unsigned char *buf, uint32_t buflen, GxTraceData *data, uint32_t *offset);
static int unpackGxRoutingRuleDefinition(unsigned char *buf, uint32_t buflen, GxRoutingRuleDefinition *data, uint32_t *offset);
static int unpackGxMdtConfiguration(unsigned char *buf, uint32_t buflen, GxMdtConfiguration *data, uint32_t *offset);
static int unpackGxChargingRuleRemove(unsigned char *buf, uint32_t buflen, GxChargingRuleRemove *data, uint32_t *offset);
static int unpackGxAllocationRetentionPriority(unsigned char *buf, uint32_t buflen, GxAllocationRetentionPriority *data, uint32_t *offset);
static int unpackGxDefaultEpsBearerQos(unsigned char *buf, uint32_t buflen, GxDefaultEpsBearerQos *data, uint32_t *offset);
static int unpackGxRoutingRuleReport(unsigned char *buf, uint32_t buflen, GxRoutingRuleReport *data, uint32_t *offset);
static int unpackGxUserEquipmentInfo(unsigned char *buf, uint32_t buflen, GxUserEquipmentInfo *data, uint32_t *offset);
static int unpackGxSupportedFeatures(unsigned char *buf, uint32_t buflen, GxSupportedFeatures *data, uint32_t *offset);
static int unpackGxFixedUserLocationInfo(unsigned char *buf, uint32_t buflen, GxFixedUserLocationInfo *data, uint32_t *offset);
static int unpackGxDefaultQosInformation(unsigned char *buf, uint32_t buflen, GxDefaultQosInformation *data, uint32_t *offset);
static int unpackGxLoad(unsigned char *buf, uint32_t buflen, GxLoad *data, uint32_t *offset);
static int unpackGxRedirectServer(unsigned char *buf, uint32_t buflen, GxRedirectServer *data, uint32_t *offset);
static int unpackGxOcSupportedFeatures(unsigned char *buf, uint32_t buflen, GxOcSupportedFeatures *data, uint32_t *offset);
static int unpackGxPacketFilterInformation(unsigned char *buf, uint32_t buflen, GxPacketFilterInformation *data, uint32_t *offset);
static int unpackGxSubscriptionId(unsigned char *buf, uint32_t buflen, GxSubscriptionId *data, uint32_t *offset);
static int unpackGxChargingInformation(unsigned char *buf, uint32_t buflen, GxChargingInformation *data, uint32_t *offset);
static int unpackGxUsageMonitoringInformation(unsigned char *buf, uint32_t buflen, GxUsageMonitoringInformation *data, uint32_t *offset);
static int unpackGxChargingRuleReport(unsigned char *buf, uint32_t buflen, GxChargingRuleReport *data, uint32_t *offset);
static int unpackGxRedirectInformation(unsigned char *buf, uint32_t buflen, GxRedirectInformation *data, uint32_t *offset);
static int unpackGxFailedAvp(unsigned char *buf, uint32_t buflen, GxFailedAvp *data, uint32_t *offset);
static int unpackGxRoutingRuleRemove(unsigned char *buf, uint32_t buflen, GxRoutingRuleRemove *data, uint32_t *offset);
static int unpackGxRoutingFilter(unsigned char *buf, uint32_t buflen, GxRoutingFilter *data, uint32_t *offset);
static int unpackGxCoaInformation(unsigned char *buf, uint32_t buflen, GxCoaInformation *data, uint32_t *offset);
static int unpackGxGrantedServiceUnit(unsigned char *buf, uint32_t buflen, GxGrantedServiceUnit *data, uint32_t *offset);
static int unpackGxCcMoney(unsigned char *buf, uint32_t buflen, GxCcMoney *data, uint32_t *offset);
static int unpackGxApplicationDetectionInformation(unsigned char *buf, uint32_t buflen, GxApplicationDetectionInformation *data, uint32_t *offset);
static int unpackGxFlows(unsigned char *buf, uint32_t buflen, GxFlows *data, uint32_t *offset);
static int unpackGxUserCsgInformation(unsigned char *buf, uint32_t buflen, GxUserCsgInformation *data, uint32_t *offset);

/*******************************************************************************/
/* message length calculation functions                                        */
/*******************************************************************************/

/*
*
*       Fun:    gx_rar_calc_length
*
*       Desc:   Calculate the length for the Re-Auth-Request Message
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
uint32_t gx_rar_calc_length
(
    GxRAR *data
)
{
    uint32_t length = sizeof(uint32_t);

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_OCTETSTRING( length, data, session_id );
    CALCLEN_BASIC( length, data, drmp );
    CALCLEN_BASIC( length, data, auth_application_id );
    CALCLEN_OCTETSTRING( length, data, origin_host );
    CALCLEN_OCTETSTRING( length, data, origin_realm );
    CALCLEN_OCTETSTRING( length, data, destination_realm );
    CALCLEN_OCTETSTRING( length, data, destination_host );
    CALCLEN_BASIC( length, data, re_auth_request_type );
    CALCLEN_BASIC( length, data, session_release_cause );
    CALCLEN_BASIC( length, data, origin_state_id );
    CALCLEN_STRUCT( length, data, oc_supported_features, calcLengthGxOcSupportedFeatures );
    CALCLEN_LIST_BASIC( length, data, event_trigger );
    CALCLEN_STRUCT( length, data, event_report_indication, calcLengthGxEventReportIndication );
    CALCLEN_LIST_STRUCT( length, data, charging_rule_remove, calcLengthGxChargingRuleRemove );
    CALCLEN_LIST_STRUCT( length, data, charging_rule_install, calcLengthGxChargingRuleInstall );
    CALCLEN_STRUCT( length, data, default_eps_bearer_qos, calcLengthGxDefaultEpsBearerQos );
    CALCLEN_LIST_STRUCT( length, data, qos_information, calcLengthGxQosInformation );
    CALCLEN_STRUCT( length, data, default_qos_information, calcLengthGxDefaultQosInformation );
    CALCLEN_BASIC( length, data, revalidation_time );
    CALCLEN_LIST_STRUCT( length, data, usage_monitoring_information, calcLengthGxUsageMonitoringInformation );
    CALCLEN_BASIC( length, data, pcscf_restoration_indication );
    CALCLEN_LIST_STRUCT( length, data, conditional_policy_information, calcLengthGxConditionalPolicyInformation );
    CALCLEN_BASIC( length, data, removal_of_access );
    CALCLEN_BASIC( length, data, ip_can_type );
    CALCLEN_STRUCT( length, data, pra_install, calcLengthGxPraInstall );
    CALCLEN_STRUCT( length, data, pra_remove, calcLengthGxPraRemove );
    CALCLEN_LIST_BASIC( length, data, csg_information_reporting );
    CALCLEN_LIST_STRUCT( length, data, proxy_info, calcLengthGxProxyInfo );
    CALCLEN_LIST_OCTETSTRING( length, data, route_record );

    return length;
}

/*
*
*       Fun:    gx_raa_calc_length
*
*       Desc:   Calculate the length for the Re-Auth-Answer Message
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
uint32_t gx_raa_calc_length
(
    GxRAA *data
)
{
    uint32_t length = sizeof(uint32_t);

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_OCTETSTRING( length, data, session_id );
    CALCLEN_BASIC( length, data, drmp );
    CALCLEN_OCTETSTRING( length, data, origin_host );
    CALCLEN_OCTETSTRING( length, data, origin_realm );
    CALCLEN_BASIC( length, data, result_code );
    CALCLEN_STRUCT( length, data, experimental_result, calcLengthGxExperimentalResult );
    CALCLEN_BASIC( length, data, origin_state_id );
    CALCLEN_STRUCT( length, data, oc_supported_features, calcLengthGxOcSupportedFeatures );
    CALCLEN_STRUCT( length, data, oc_olr, calcLengthGxOcOlr );
    CALCLEN_BASIC( length, data, ip_can_type );
    CALCLEN_BASIC( length, data, rat_type );
    CALCLEN_BASIC( length, data, an_trusted );
    CALCLEN_LIST_BASIC( length, data, an_gw_address );
    CALCLEN_OCTETSTRING( length, data, tgpp_sgsn_mcc_mnc );
    CALCLEN_OCTETSTRING( length, data, tgpp_sgsn_address );
    CALCLEN_OCTETSTRING( length, data, tgpp_sgsn_ipv6_address );
    CALCLEN_OCTETSTRING( length, data, rai );
    CALCLEN_OCTETSTRING( length, data, tgpp_user_location_info );
    CALCLEN_BASIC( length, data, user_location_info_time );
    CALCLEN_BASIC( length, data, netloc_access_support );
    CALCLEN_STRUCT( length, data, user_csg_information, calcLengthGxUserCsgInformation );
    CALCLEN_OCTETSTRING( length, data, tgpp_ms_timezone );
    CALCLEN_STRUCT( length, data, default_qos_information, calcLengthGxDefaultQosInformation );
    CALCLEN_LIST_STRUCT( length, data, charging_rule_report, calcLengthGxChargingRuleReport );
    CALCLEN_OCTETSTRING( length, data, error_message );
    CALCLEN_OCTETSTRING( length, data, error_reporting_host );
    CALCLEN_STRUCT( length, data, failed_avp, calcLengthGxFailedAvp );
    CALCLEN_LIST_STRUCT( length, data, proxy_info, calcLengthGxProxyInfo );

    return length;
}

/*
*
*       Fun:    gx_cca_calc_length
*
*       Desc:   Calculate the length for the Credit-Control-Answer Message
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
uint32_t gx_cca_calc_length
(
    GxCCA *data
)
{
    uint32_t length = sizeof(uint32_t);

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_OCTETSTRING( length, data, session_id );
    CALCLEN_BASIC( length, data, drmp );
    CALCLEN_BASIC( length, data, auth_application_id );
    CALCLEN_OCTETSTRING( length, data, origin_host );
    CALCLEN_OCTETSTRING( length, data, origin_realm );
    CALCLEN_BASIC( length, data, result_code );
    CALCLEN_STRUCT( length, data, experimental_result, calcLengthGxExperimentalResult );
    CALCLEN_BASIC( length, data, cc_request_type );
    CALCLEN_BASIC( length, data, cc_request_number );
    CALCLEN_STRUCT( length, data, oc_supported_features, calcLengthGxOcSupportedFeatures );
    CALCLEN_STRUCT( length, data, oc_olr, calcLengthGxOcOlr );
    CALCLEN_LIST_STRUCT( length, data, supported_features, calcLengthGxSupportedFeatures );
    CALCLEN_BASIC( length, data, bearer_control_mode );
    CALCLEN_LIST_BASIC( length, data, event_trigger );
    CALCLEN_STRUCT( length, data, event_report_indication, calcLengthGxEventReportIndication );
    CALCLEN_BASIC( length, data, origin_state_id );
    CALCLEN_LIST_OCTETSTRING( length, data, redirect_host );
    CALCLEN_BASIC( length, data, redirect_host_usage );
    CALCLEN_BASIC( length, data, redirect_max_cache_time );
    CALCLEN_LIST_STRUCT( length, data, charging_rule_remove, calcLengthGxChargingRuleRemove );
    CALCLEN_LIST_STRUCT( length, data, charging_rule_install, calcLengthGxChargingRuleInstall );
    CALCLEN_STRUCT( length, data, charging_information, calcLengthGxChargingInformation );
    CALCLEN_BASIC( length, data, online );
    CALCLEN_BASIC( length, data, offline );
    CALCLEN_LIST_STRUCT( length, data, qos_information, calcLengthGxQosInformation );
    CALCLEN_BASIC( length, data, revalidation_time );
    CALCLEN_STRUCT( length, data, default_eps_bearer_qos, calcLengthGxDefaultEpsBearerQos );
    CALCLEN_STRUCT( length, data, default_qos_information, calcLengthGxDefaultQosInformation );
    CALCLEN_BASIC( length, data, bearer_usage );
    CALCLEN_LIST_STRUCT( length, data, usage_monitoring_information, calcLengthGxUsageMonitoringInformation );
    CALCLEN_LIST_BASIC( length, data, csg_information_reporting );
    CALCLEN_STRUCT( length, data, user_csg_information, calcLengthGxUserCsgInformation );
    CALCLEN_STRUCT( length, data, pra_install, calcLengthGxPraInstall );
    CALCLEN_STRUCT( length, data, pra_remove, calcLengthGxPraRemove );
    CALCLEN_STRUCT( length, data, presence_reporting_area_information, calcLengthGxPresenceReportingAreaInformation );
    CALCLEN_BASIC( length, data, session_release_cause );
    CALCLEN_BASIC( length, data, nbifom_support );
    CALCLEN_BASIC( length, data, nbifom_mode );
    CALCLEN_BASIC( length, data, default_access );
    CALCLEN_BASIC( length, data, ran_rule_support );
    CALCLEN_LIST_STRUCT( length, data, routing_rule_report, calcLengthGxRoutingRuleReport );
    CALCLEN_LIST_STRUCT( length, data, conditional_policy_information, calcLengthGxConditionalPolicyInformation );
    CALCLEN_BASIC( length, data, removal_of_access );
    CALCLEN_BASIC( length, data, ip_can_type );
    CALCLEN_OCTETSTRING( length, data, error_message );
    CALCLEN_OCTETSTRING( length, data, error_reporting_host );
    CALCLEN_STRUCT( length, data, failed_avp, calcLengthGxFailedAvp );
    CALCLEN_LIST_STRUCT( length, data, proxy_info, calcLengthGxProxyInfo );
    CALCLEN_LIST_OCTETSTRING( length, data, route_record );
    CALCLEN_LIST_STRUCT( length, data, load, calcLengthGxLoad );

    return length;
}

/*
*
*       Fun:    gx_ccr_calc_length
*
*       Desc:   Calculate the length for the Credit-Control-Request Message
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
uint32_t gx_ccr_calc_length
(
    GxCCR *data
)
{
    uint32_t length = sizeof(uint32_t);

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_OCTETSTRING( length, data, session_id );
    CALCLEN_BASIC( length, data, drmp );
    CALCLEN_BASIC( length, data, auth_application_id );
    CALCLEN_OCTETSTRING( length, data, origin_host );
    CALCLEN_OCTETSTRING( length, data, origin_realm );
    CALCLEN_OCTETSTRING( length, data, destination_realm );
    CALCLEN_OCTETSTRING( length, data, service_context_id );
    CALCLEN_BASIC( length, data, cc_request_type );
    CALCLEN_BASIC( length, data, cc_request_number );
    CALCLEN_BASIC( length, data, credit_management_status );
    CALCLEN_OCTETSTRING( length, data, destination_host );
    CALCLEN_BASIC( length, data, origin_state_id );
    CALCLEN_LIST_STRUCT( length, data, subscription_id, calcLengthGxSubscriptionId );
    CALCLEN_STRUCT( length, data, oc_supported_features, calcLengthGxOcSupportedFeatures );
    CALCLEN_LIST_STRUCT( length, data, supported_features, calcLengthGxSupportedFeatures );
    CALCLEN_STRUCT( length, data, tdf_information, calcLengthGxTdfInformation );
    CALCLEN_BASIC( length, data, network_request_support );
    CALCLEN_LIST_STRUCT( length, data, packet_filter_information, calcLengthGxPacketFilterInformation );
    CALCLEN_BASIC( length, data, packet_filter_operation );
    CALCLEN_OCTETSTRING( length, data, bearer_identifier );
    CALCLEN_BASIC( length, data, bearer_operation );
    CALCLEN_BASIC( length, data, dynamic_address_flag );
    CALCLEN_BASIC( length, data, dynamic_address_flag_extension );
    CALCLEN_BASIC( length, data, pdn_connection_charging_id );
    CALCLEN_OCTETSTRING( length, data, framed_ip_address );
    CALCLEN_OCTETSTRING( length, data, framed_ipv6_prefix );
    CALCLEN_BASIC( length, data, ip_can_type );
    CALCLEN_OCTETSTRING( length, data, tgpp_rat_type );
    CALCLEN_BASIC( length, data, an_trusted );
    CALCLEN_BASIC( length, data, rat_type );
    CALCLEN_BASIC( length, data, termination_cause );
    CALCLEN_STRUCT( length, data, user_equipment_info, calcLengthGxUserEquipmentInfo );
    CALCLEN_STRUCT( length, data, qos_information, calcLengthGxQosInformation );
    CALCLEN_BASIC( length, data, qos_negotiation );
    CALCLEN_BASIC( length, data, qos_upgrade );
    CALCLEN_STRUCT( length, data, default_eps_bearer_qos, calcLengthGxDefaultEpsBearerQos );
    CALCLEN_STRUCT( length, data, default_qos_information, calcLengthGxDefaultQosInformation );
    CALCLEN_LIST_BASIC( length, data, an_gw_address );
    CALCLEN_BASIC( length, data, an_gw_status );
    CALCLEN_OCTETSTRING( length, data, tgpp_sgsn_mcc_mnc );
    CALCLEN_OCTETSTRING( length, data, tgpp_sgsn_address );
    CALCLEN_OCTETSTRING( length, data, tgpp_sgsn_ipv6_address );
    CALCLEN_OCTETSTRING( length, data, tgpp_ggsn_address );
    CALCLEN_OCTETSTRING( length, data, tgpp_ggsn_ipv6_address );
    CALCLEN_OCTETSTRING( length, data, tgpp_selection_mode );
    CALCLEN_OCTETSTRING( length, data, rai );
    CALCLEN_OCTETSTRING( length, data, tgpp_user_location_info );
    CALCLEN_STRUCT( length, data, fixed_user_location_info, calcLengthGxFixedUserLocationInfo );
    CALCLEN_BASIC( length, data, user_location_info_time );
    CALCLEN_STRUCT( length, data, user_csg_information, calcLengthGxUserCsgInformation );
    CALCLEN_OCTETSTRING( length, data, twan_identifier );
    CALCLEN_OCTETSTRING( length, data, tgpp_ms_timezone );
    CALCLEN_LIST_OCTETSTRING( length, data, ran_nas_release_cause );
    CALCLEN_OCTETSTRING( length, data, tgpp_charging_characteristics );
    CALCLEN_OCTETSTRING( length, data, called_station_id );
    CALCLEN_OCTETSTRING( length, data, pdn_connection_id );
    CALCLEN_BASIC( length, data, bearer_usage );
    CALCLEN_BASIC( length, data, online );
    CALCLEN_BASIC( length, data, offline );
    CALCLEN_LIST_STRUCT( length, data, tft_packet_filter_information, calcLengthGxTftPacketFilterInformation );
    CALCLEN_LIST_STRUCT( length, data, charging_rule_report, calcLengthGxChargingRuleReport );
    CALCLEN_LIST_STRUCT( length, data, application_detection_information, calcLengthGxApplicationDetectionInformation );
    CALCLEN_LIST_BASIC( length, data, event_trigger );
    CALCLEN_STRUCT( length, data, event_report_indication, calcLengthGxEventReportIndication );
    CALCLEN_BASIC( length, data, access_network_charging_address );
    CALCLEN_LIST_STRUCT( length, data, access_network_charging_identifier_gx, calcLengthGxAccessNetworkChargingIdentifierGx );
    CALCLEN_LIST_STRUCT( length, data, coa_information, calcLengthGxCoaInformation );
    CALCLEN_LIST_STRUCT( length, data, usage_monitoring_information, calcLengthGxUsageMonitoringInformation );
    CALCLEN_BASIC( length, data, nbifom_support );
    CALCLEN_BASIC( length, data, nbifom_mode );
    CALCLEN_BASIC( length, data, default_access );
    CALCLEN_BASIC( length, data, origination_time_stamp );
    CALCLEN_BASIC( length, data, maximum_wait_time );
    CALCLEN_BASIC( length, data, access_availability_change_reason );
    CALCLEN_STRUCT( length, data, routing_rule_install, calcLengthGxRoutingRuleInstall );
    CALCLEN_STRUCT( length, data, routing_rule_remove, calcLengthGxRoutingRuleRemove );
    CALCLEN_BASIC( length, data, henb_local_ip_address );
    CALCLEN_BASIC( length, data, ue_local_ip_address );
    CALCLEN_BASIC( length, data, udp_source_port );
    CALCLEN_BASIC( length, data, tcp_source_port );
    CALCLEN_LIST_STRUCT( length, data, presence_reporting_area_information, calcLengthGxPresenceReportingAreaInformation );
    CALCLEN_OCTETSTRING( length, data, logical_access_id );
    CALCLEN_OCTETSTRING( length, data, physical_access_id );
    CALCLEN_LIST_STRUCT( length, data, proxy_info, calcLengthGxProxyInfo );
    CALCLEN_LIST_OCTETSTRING( length, data, route_record );
    CALCLEN_BASIC( length, data, tgpp_ps_data_off_status );

    return length;
}


/*******************************************************************************/
/*  message pack functions                                                     */
/*******************************************************************************/

/*
*
*       Fun:    gx_rar_pack
*
*       Desc:   Pack the contents of the Re-Auth-Request Message
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
int gx_rar_pack
(
    GxRAR *data,
    unsigned char *buf,
    uint32_t buflen
)
{
    uint32_t _offset = sizeof(uint32_t);
    uint32_t *offset = &_offset;

    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_OCTETSTRING( data, session_id, buf, buflen, offset );
    PACK_BASIC( data, drmp, buf, buflen, offset );
    PACK_BASIC( data, auth_application_id, buf, buflen, offset );
    PACK_OCTETSTRING( data, origin_host, buf, buflen, offset );
    PACK_OCTETSTRING( data, origin_realm, buf, buflen, offset );
    PACK_OCTETSTRING( data, destination_realm, buf, buflen, offset );
    PACK_OCTETSTRING( data, destination_host, buf, buflen, offset );
    PACK_BASIC( data, re_auth_request_type, buf, buflen, offset );
    PACK_BASIC( data, session_release_cause, buf, buflen, offset );
    PACK_BASIC( data, origin_state_id, buf, buflen, offset );
    PACK_STRUCT( data, oc_supported_features, buf, buflen, offset, packGxOcSupportedFeatures );
    PACK_LIST_BASIC( data, event_trigger, buf, buflen, offset );
    PACK_STRUCT( data, event_report_indication, buf, buflen, offset, packGxEventReportIndication );
    PACK_LIST_STRUCT( data, charging_rule_remove, buf, buflen, offset, packGxChargingRuleRemove );
    PACK_LIST_STRUCT( data, charging_rule_install, buf, buflen, offset, packGxChargingRuleInstall );
    PACK_STRUCT( data, default_eps_bearer_qos, buf, buflen, offset, packGxDefaultEpsBearerQos );
    PACK_LIST_STRUCT( data, qos_information, buf, buflen, offset, packGxQosInformation );
    PACK_STRUCT( data, default_qos_information, buf, buflen, offset, packGxDefaultQosInformation );
    PACK_BASIC( data, revalidation_time, buf, buflen, offset );
    PACK_LIST_STRUCT( data, usage_monitoring_information, buf, buflen, offset, packGxUsageMonitoringInformation );
    PACK_BASIC( data, pcscf_restoration_indication, buf, buflen, offset );
    PACK_LIST_STRUCT( data, conditional_policy_information, buf, buflen, offset, packGxConditionalPolicyInformation );
    PACK_BASIC( data, removal_of_access, buf, buflen, offset );
    PACK_BASIC( data, ip_can_type, buf, buflen, offset );
    PACK_STRUCT( data, pra_install, buf, buflen, offset, packGxPraInstall );
    PACK_STRUCT( data, pra_remove, buf, buflen, offset, packGxPraRemove );
    PACK_LIST_BASIC( data, csg_information_reporting, buf, buflen, offset );
    PACK_LIST_STRUCT( data, proxy_info, buf, buflen, offset, packGxProxyInfo );
    PACK_LIST_OCTETSTRING( data, route_record, buf, buflen, offset );

    *((uint32_t*)buf) = _offset;

    return _offset == buflen;
}

/*
*
*       Fun:    gx_raa_pack
*
*       Desc:   Pack the contents of the Re-Auth-Answer Message
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
int gx_raa_pack
(
    GxRAA *data,
    unsigned char *buf,
    uint32_t buflen
)
{
    uint32_t _offset = sizeof(uint32_t);
    uint32_t *offset = &_offset;

    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_OCTETSTRING( data, session_id, buf, buflen, offset );
    PACK_BASIC( data, drmp, buf, buflen, offset );
    PACK_OCTETSTRING( data, origin_host, buf, buflen, offset );
    PACK_OCTETSTRING( data, origin_realm, buf, buflen, offset );
    PACK_BASIC( data, result_code, buf, buflen, offset );
    PACK_STRUCT( data, experimental_result, buf, buflen, offset, packGxExperimentalResult );
    PACK_BASIC( data, origin_state_id, buf, buflen, offset );
    PACK_STRUCT( data, oc_supported_features, buf, buflen, offset, packGxOcSupportedFeatures );
    PACK_STRUCT( data, oc_olr, buf, buflen, offset, packGxOcOlr );
    PACK_BASIC( data, ip_can_type, buf, buflen, offset );
    PACK_BASIC( data, rat_type, buf, buflen, offset );
    PACK_BASIC( data, an_trusted, buf, buflen, offset );
    PACK_LIST_BASIC( data, an_gw_address, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp_sgsn_mcc_mnc, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp_sgsn_address, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp_sgsn_ipv6_address, buf, buflen, offset );
    PACK_OCTETSTRING( data, rai, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp_user_location_info, buf, buflen, offset );
    PACK_BASIC( data, user_location_info_time, buf, buflen, offset );
    PACK_BASIC( data, netloc_access_support, buf, buflen, offset );
    PACK_STRUCT( data, user_csg_information, buf, buflen, offset, packGxUserCsgInformation );
    PACK_OCTETSTRING( data, tgpp_ms_timezone, buf, buflen, offset );
    PACK_STRUCT( data, default_qos_information, buf, buflen, offset, packGxDefaultQosInformation );
    PACK_LIST_STRUCT( data, charging_rule_report, buf, buflen, offset, packGxChargingRuleReport );
    PACK_OCTETSTRING( data, error_message, buf, buflen, offset );
    PACK_OCTETSTRING( data, error_reporting_host, buf, buflen, offset );
    PACK_STRUCT( data, failed_avp, buf, buflen, offset, packGxFailedAvp );
    PACK_LIST_STRUCT( data, proxy_info, buf, buflen, offset, packGxProxyInfo );

    *((uint32_t*)buf) = _offset;

    return _offset == buflen;
}

/*
*
*       Fun:    gx_cca_pack
*
*       Desc:   Pack the contents of the Credit-Control-Answer Message
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
int gx_cca_pack
(
    GxCCA *data,
    unsigned char *buf,
    uint32_t buflen
)
{
    uint32_t _offset = sizeof(uint32_t);
    uint32_t *offset = &_offset;

    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_OCTETSTRING( data, session_id, buf, buflen, offset );
    PACK_BASIC( data, drmp, buf, buflen, offset );
    PACK_BASIC( data, auth_application_id, buf, buflen, offset );
    PACK_OCTETSTRING( data, origin_host, buf, buflen, offset );
    PACK_OCTETSTRING( data, origin_realm, buf, buflen, offset );
    PACK_BASIC( data, result_code, buf, buflen, offset );
    PACK_STRUCT( data, experimental_result, buf, buflen, offset, packGxExperimentalResult );
    PACK_BASIC( data, cc_request_type, buf, buflen, offset );
    PACK_BASIC( data, cc_request_number, buf, buflen, offset );
    PACK_STRUCT( data, oc_supported_features, buf, buflen, offset, packGxOcSupportedFeatures );
    PACK_STRUCT( data, oc_olr, buf, buflen, offset, packGxOcOlr );
    PACK_LIST_STRUCT( data, supported_features, buf, buflen, offset, packGxSupportedFeatures );
    PACK_BASIC( data, bearer_control_mode, buf, buflen, offset );
    PACK_LIST_BASIC( data, event_trigger, buf, buflen, offset );
    PACK_STRUCT( data, event_report_indication, buf, buflen, offset, packGxEventReportIndication );
    PACK_BASIC( data, origin_state_id, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, redirect_host, buf, buflen, offset );
    PACK_BASIC( data, redirect_host_usage, buf, buflen, offset );
    PACK_BASIC( data, redirect_max_cache_time, buf, buflen, offset );
    PACK_LIST_STRUCT( data, charging_rule_remove, buf, buflen, offset, packGxChargingRuleRemove );
    PACK_LIST_STRUCT( data, charging_rule_install, buf, buflen, offset, packGxChargingRuleInstall );
    PACK_STRUCT( data, charging_information, buf, buflen, offset, packGxChargingInformation );
    PACK_BASIC( data, online, buf, buflen, offset );
    PACK_BASIC( data, offline, buf, buflen, offset );
    PACK_LIST_STRUCT( data, qos_information, buf, buflen, offset, packGxQosInformation );
    PACK_BASIC( data, revalidation_time, buf, buflen, offset );
    PACK_STRUCT( data, default_eps_bearer_qos, buf, buflen, offset, packGxDefaultEpsBearerQos );
    PACK_STRUCT( data, default_qos_information, buf, buflen, offset, packGxDefaultQosInformation );
    PACK_BASIC( data, bearer_usage, buf, buflen, offset );
    PACK_LIST_STRUCT( data, usage_monitoring_information, buf, buflen, offset, packGxUsageMonitoringInformation );
    PACK_LIST_BASIC( data, csg_information_reporting, buf, buflen, offset );
    PACK_STRUCT( data, user_csg_information, buf, buflen, offset, packGxUserCsgInformation );
    PACK_STRUCT( data, pra_install, buf, buflen, offset, packGxPraInstall );
    PACK_STRUCT( data, pra_remove, buf, buflen, offset, packGxPraRemove );
    PACK_STRUCT( data, presence_reporting_area_information, buf, buflen, offset, packGxPresenceReportingAreaInformation );
    PACK_BASIC( data, session_release_cause, buf, buflen, offset );
    PACK_BASIC( data, nbifom_support, buf, buflen, offset );
    PACK_BASIC( data, nbifom_mode, buf, buflen, offset );
    PACK_BASIC( data, default_access, buf, buflen, offset );
    PACK_BASIC( data, ran_rule_support, buf, buflen, offset );
    PACK_LIST_STRUCT( data, routing_rule_report, buf, buflen, offset, packGxRoutingRuleReport );
    PACK_LIST_STRUCT( data, conditional_policy_information, buf, buflen, offset, packGxConditionalPolicyInformation );
    PACK_BASIC( data, removal_of_access, buf, buflen, offset );
    PACK_BASIC( data, ip_can_type, buf, buflen, offset );
    PACK_OCTETSTRING( data, error_message, buf, buflen, offset );
    PACK_OCTETSTRING( data, error_reporting_host, buf, buflen, offset );
    PACK_STRUCT( data, failed_avp, buf, buflen, offset, packGxFailedAvp );
    PACK_LIST_STRUCT( data, proxy_info, buf, buflen, offset, packGxProxyInfo );
    PACK_LIST_OCTETSTRING( data, route_record, buf, buflen, offset );
    PACK_LIST_STRUCT( data, load, buf, buflen, offset, packGxLoad );

    *((uint32_t*)buf) = _offset;

    return _offset == buflen;
}

/*
*
*       Fun:    gx_ccr_pack
*
*       Desc:   Pack the contents of the Credit-Control-Request Message
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
int gx_ccr_pack
(
    GxCCR *data,
    unsigned char *buf,
    uint32_t buflen
)
{
    uint32_t _offset = sizeof(uint32_t);
    uint32_t *offset = &_offset;

    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_OCTETSTRING( data, session_id, buf, buflen, offset );
    PACK_BASIC( data, drmp, buf, buflen, offset );
    PACK_BASIC( data, auth_application_id, buf, buflen, offset );
    PACK_OCTETSTRING( data, origin_host, buf, buflen, offset );
    PACK_OCTETSTRING( data, origin_realm, buf, buflen, offset );
    PACK_OCTETSTRING( data, destination_realm, buf, buflen, offset );
    PACK_OCTETSTRING( data, service_context_id, buf, buflen, offset );
    PACK_BASIC( data, cc_request_type, buf, buflen, offset );
    PACK_BASIC( data, cc_request_number, buf, buflen, offset );
    PACK_BASIC( data, credit_management_status, buf, buflen, offset );
    PACK_OCTETSTRING( data, destination_host, buf, buflen, offset );
    PACK_BASIC( data, origin_state_id, buf, buflen, offset );
    PACK_LIST_STRUCT( data, subscription_id, buf, buflen, offset, packGxSubscriptionId );
    PACK_STRUCT( data, oc_supported_features, buf, buflen, offset, packGxOcSupportedFeatures );
    PACK_LIST_STRUCT( data, supported_features, buf, buflen, offset, packGxSupportedFeatures );
    PACK_STRUCT( data, tdf_information, buf, buflen, offset, packGxTdfInformation );
    PACK_BASIC( data, network_request_support, buf, buflen, offset );
    PACK_LIST_STRUCT( data, packet_filter_information, buf, buflen, offset, packGxPacketFilterInformation );
    PACK_BASIC( data, packet_filter_operation, buf, buflen, offset );
    PACK_OCTETSTRING( data, bearer_identifier, buf, buflen, offset );
    PACK_BASIC( data, bearer_operation, buf, buflen, offset );
    PACK_BASIC( data, dynamic_address_flag, buf, buflen, offset );
    PACK_BASIC( data, dynamic_address_flag_extension, buf, buflen, offset );
    PACK_BASIC( data, pdn_connection_charging_id, buf, buflen, offset );
    PACK_OCTETSTRING( data, framed_ip_address, buf, buflen, offset );
    PACK_OCTETSTRING( data, framed_ipv6_prefix, buf, buflen, offset );
    PACK_BASIC( data, ip_can_type, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp_rat_type, buf, buflen, offset );
    PACK_BASIC( data, an_trusted, buf, buflen, offset );
    PACK_BASIC( data, rat_type, buf, buflen, offset );
    PACK_BASIC( data, termination_cause, buf, buflen, offset );
    PACK_STRUCT( data, user_equipment_info, buf, buflen, offset, packGxUserEquipmentInfo );
    PACK_STRUCT( data, qos_information, buf, buflen, offset, packGxQosInformation );
    PACK_BASIC( data, qos_negotiation, buf, buflen, offset );
    PACK_BASIC( data, qos_upgrade, buf, buflen, offset );
    PACK_STRUCT( data, default_eps_bearer_qos, buf, buflen, offset, packGxDefaultEpsBearerQos );
    PACK_STRUCT( data, default_qos_information, buf, buflen, offset, packGxDefaultQosInformation );
    PACK_LIST_BASIC( data, an_gw_address, buf, buflen, offset );
    PACK_BASIC( data, an_gw_status, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp_sgsn_mcc_mnc, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp_sgsn_address, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp_sgsn_ipv6_address, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp_ggsn_address, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp_ggsn_ipv6_address, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp_selection_mode, buf, buflen, offset );
    PACK_OCTETSTRING( data, rai, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp_user_location_info, buf, buflen, offset );
    PACK_STRUCT( data, fixed_user_location_info, buf, buflen, offset, packGxFixedUserLocationInfo );
    PACK_BASIC( data, user_location_info_time, buf, buflen, offset );
    PACK_STRUCT( data, user_csg_information, buf, buflen, offset, packGxUserCsgInformation );
    PACK_OCTETSTRING( data, twan_identifier, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp_ms_timezone, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, ran_nas_release_cause, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp_charging_characteristics, buf, buflen, offset );
    PACK_OCTETSTRING( data, called_station_id, buf, buflen, offset );
    PACK_OCTETSTRING( data, pdn_connection_id, buf, buflen, offset );
    PACK_BASIC( data, bearer_usage, buf, buflen, offset );
    PACK_BASIC( data, online, buf, buflen, offset );
    PACK_BASIC( data, offline, buf, buflen, offset );
    PACK_LIST_STRUCT( data, tft_packet_filter_information, buf, buflen, offset, packGxTftPacketFilterInformation );
    PACK_LIST_STRUCT( data, charging_rule_report, buf, buflen, offset, packGxChargingRuleReport );
    PACK_LIST_STRUCT( data, application_detection_information, buf, buflen, offset, packGxApplicationDetectionInformation );
    PACK_LIST_BASIC( data, event_trigger, buf, buflen, offset );
    PACK_STRUCT( data, event_report_indication, buf, buflen, offset, packGxEventReportIndication );
    PACK_BASIC( data, access_network_charging_address, buf, buflen, offset );
    PACK_LIST_STRUCT( data, access_network_charging_identifier_gx, buf, buflen, offset, packGxAccessNetworkChargingIdentifierGx );
    PACK_LIST_STRUCT( data, coa_information, buf, buflen, offset, packGxCoaInformation );
    PACK_LIST_STRUCT( data, usage_monitoring_information, buf, buflen, offset, packGxUsageMonitoringInformation );
    PACK_BASIC( data, nbifom_support, buf, buflen, offset );
    PACK_BASIC( data, nbifom_mode, buf, buflen, offset );
    PACK_BASIC( data, default_access, buf, buflen, offset );
    PACK_BASIC( data, origination_time_stamp, buf, buflen, offset );
    PACK_BASIC( data, maximum_wait_time, buf, buflen, offset );
    PACK_BASIC( data, access_availability_change_reason, buf, buflen, offset );
    PACK_STRUCT( data, routing_rule_install, buf, buflen, offset, packGxRoutingRuleInstall );
    PACK_STRUCT( data, routing_rule_remove, buf, buflen, offset, packGxRoutingRuleRemove );
    PACK_BASIC( data, henb_local_ip_address, buf, buflen, offset );
    PACK_BASIC( data, ue_local_ip_address, buf, buflen, offset );
    PACK_BASIC( data, udp_source_port, buf, buflen, offset );
    PACK_BASIC( data, tcp_source_port, buf, buflen, offset );
    PACK_LIST_STRUCT( data, presence_reporting_area_information, buf, buflen, offset, packGxPresenceReportingAreaInformation );
    PACK_OCTETSTRING( data, logical_access_id, buf, buflen, offset );
    PACK_OCTETSTRING( data, physical_access_id, buf, buflen, offset );
    PACK_LIST_STRUCT( data, proxy_info, buf, buflen, offset, packGxProxyInfo );
    PACK_LIST_OCTETSTRING( data, route_record, buf, buflen, offset );
    PACK_BASIC( data, tgpp_ps_data_off_status, buf, buflen, offset );

    *((uint32_t*)buf) = _offset;

    return _offset == buflen;
}

/*******************************************************************************/
/* message unpack functions                                                    */
/*******************************************************************************/

/*
*
*       Fun:    gx_rar_unpack
*
*       Desc:   Unpack the specified buffer into the Re-Auth-Request Message
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
int gx_rar_unpack
(
    unsigned char *buf,
    GxRAR *data
)
{
    uint32_t length = *((uint32_t*)buf);
    uint32_t _offset = sizeof(uint32_t);
    uint32_t *offset = &_offset;

    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_OCTETSTRING( data, session_id, buf, length, offset );
    UNPACK_BASIC( data, drmp, buf, length, offset );
    UNPACK_BASIC( data, auth_application_id, buf, length, offset );
    UNPACK_OCTETSTRING( data, origin_host, buf, length, offset );
    UNPACK_OCTETSTRING( data, origin_realm, buf, length, offset );
    UNPACK_OCTETSTRING( data, destination_realm, buf, length, offset );
    UNPACK_OCTETSTRING( data, destination_host, buf, length, offset );
    UNPACK_BASIC( data, re_auth_request_type, buf, length, offset );
    UNPACK_BASIC( data, session_release_cause, buf, length, offset );
    UNPACK_BASIC( data, origin_state_id, buf, length, offset );
    UNPACK_STRUCT( data, oc_supported_features, buf, length, offset, unpackGxOcSupportedFeatures );
    UNPACK_LIST_BASIC( data, event_trigger, int32_t, buf, length, offset );
    UNPACK_STRUCT( data, event_report_indication, buf, length, offset, unpackGxEventReportIndication );
    UNPACK_LIST_STRUCT( data, charging_rule_remove, GxChargingRuleRemove, buf, length, offset, unpackGxChargingRuleRemove );
    UNPACK_LIST_STRUCT( data, charging_rule_install, GxChargingRuleInstall, buf, length, offset, unpackGxChargingRuleInstall );
    UNPACK_STRUCT( data, default_eps_bearer_qos, buf, length, offset, unpackGxDefaultEpsBearerQos );
    UNPACK_LIST_STRUCT( data, qos_information, GxQosInformation, buf, length, offset, unpackGxQosInformation );
    UNPACK_STRUCT( data, default_qos_information, buf, length, offset, unpackGxDefaultQosInformation );
    UNPACK_BASIC( data, revalidation_time, buf, length, offset );
    UNPACK_LIST_STRUCT( data, usage_monitoring_information, GxUsageMonitoringInformation, buf, length, offset, unpackGxUsageMonitoringInformation );
    UNPACK_BASIC( data, pcscf_restoration_indication, buf, length, offset );
    UNPACK_LIST_STRUCT( data, conditional_policy_information, GxConditionalPolicyInformation, buf, length, offset, unpackGxConditionalPolicyInformation );
    UNPACK_BASIC( data, removal_of_access, buf, length, offset );
    UNPACK_BASIC( data, ip_can_type, buf, length, offset );
    UNPACK_STRUCT( data, pra_install, buf, length, offset, unpackGxPraInstall );
    UNPACK_STRUCT( data, pra_remove, buf, length, offset, unpackGxPraRemove );
    UNPACK_LIST_BASIC( data, csg_information_reporting, int32_t, buf, length, offset );
    UNPACK_LIST_STRUCT( data, proxy_info, GxProxyInfo, buf, length, offset, unpackGxProxyInfo );
    UNPACK_LIST_OCTETSTRING( data, route_record, GxRouteRecordOctetString, buf, length, offset );

    return length == _offset;
}

/*
*
*       Fun:    gx_raa_unpack
*
*       Desc:   Unpack the specified buffer into the Re-Auth-Answer Message
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
int gx_raa_unpack
(
    unsigned char *buf,
    GxRAA *data
)
{
    uint32_t length = *((uint32_t*)buf);
    uint32_t _offset = sizeof(uint32_t);
    uint32_t *offset = &_offset;

    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_OCTETSTRING( data, session_id, buf, length, offset );
    UNPACK_BASIC( data, drmp, buf, length, offset );
    UNPACK_OCTETSTRING( data, origin_host, buf, length, offset );
    UNPACK_OCTETSTRING( data, origin_realm, buf, length, offset );
    UNPACK_BASIC( data, result_code, buf, length, offset );
    UNPACK_STRUCT( data, experimental_result, buf, length, offset, unpackGxExperimentalResult );
    UNPACK_BASIC( data, origin_state_id, buf, length, offset );
    UNPACK_STRUCT( data, oc_supported_features, buf, length, offset, unpackGxOcSupportedFeatures );
    UNPACK_STRUCT( data, oc_olr, buf, length, offset, unpackGxOcOlr );
    UNPACK_BASIC( data, ip_can_type, buf, length, offset );
    UNPACK_BASIC( data, rat_type, buf, length, offset );
    UNPACK_BASIC( data, an_trusted, buf, length, offset );
    UNPACK_LIST_BASIC( data, an_gw_address, FdAddress, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp_sgsn_mcc_mnc, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp_sgsn_address, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp_sgsn_ipv6_address, buf, length, offset );
    UNPACK_OCTETSTRING( data, rai, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp_user_location_info, buf, length, offset );
    UNPACK_BASIC( data, user_location_info_time, buf, length, offset );
    UNPACK_BASIC( data, netloc_access_support, buf, length, offset );
    UNPACK_STRUCT( data, user_csg_information, buf, length, offset, unpackGxUserCsgInformation );
    UNPACK_OCTETSTRING( data, tgpp_ms_timezone, buf, length, offset );
    UNPACK_STRUCT( data, default_qos_information, buf, length, offset, unpackGxDefaultQosInformation );
    UNPACK_LIST_STRUCT( data, charging_rule_report, GxChargingRuleReport, buf, length, offset, unpackGxChargingRuleReport );
    UNPACK_OCTETSTRING( data, error_message, buf, length, offset );
    UNPACK_OCTETSTRING( data, error_reporting_host, buf, length, offset );
    UNPACK_STRUCT( data, failed_avp, buf, length, offset, unpackGxFailedAvp );
    UNPACK_LIST_STRUCT( data, proxy_info, GxProxyInfo, buf, length, offset, unpackGxProxyInfo );

    return length == _offset;
}

/*
*
*       Fun:    gx_cca_unpack
*
*       Desc:   Unpack the specified buffer into the Credit-Control-Answer Message
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
int gx_cca_unpack
(
    unsigned char *buf,
    GxCCA *data
)
{
    uint32_t length = *((uint32_t*)buf);
    uint32_t _offset = sizeof(uint32_t);
    uint32_t *offset = &_offset;

    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_OCTETSTRING( data, session_id, buf, length, offset );
    UNPACK_BASIC( data, drmp, buf, length, offset );
    UNPACK_BASIC( data, auth_application_id, buf, length, offset );
    UNPACK_OCTETSTRING( data, origin_host, buf, length, offset );
    UNPACK_OCTETSTRING( data, origin_realm, buf, length, offset );
    UNPACK_BASIC( data, result_code, buf, length, offset );
    UNPACK_STRUCT( data, experimental_result, buf, length, offset, unpackGxExperimentalResult );
    UNPACK_BASIC( data, cc_request_type, buf, length, offset );
    UNPACK_BASIC( data, cc_request_number, buf, length, offset );
    UNPACK_STRUCT( data, oc_supported_features, buf, length, offset, unpackGxOcSupportedFeatures );
    UNPACK_STRUCT( data, oc_olr, buf, length, offset, unpackGxOcOlr );
    UNPACK_LIST_STRUCT( data, supported_features, GxSupportedFeatures, buf, length, offset, unpackGxSupportedFeatures );
    UNPACK_BASIC( data, bearer_control_mode, buf, length, offset );
    UNPACK_LIST_BASIC( data, event_trigger, int32_t, buf, length, offset );
    UNPACK_STRUCT( data, event_report_indication, buf, length, offset, unpackGxEventReportIndication );
    UNPACK_BASIC( data, origin_state_id, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, redirect_host, GxRedirectHostOctetString, buf, length, offset );
    UNPACK_BASIC( data, redirect_host_usage, buf, length, offset );
    UNPACK_BASIC( data, redirect_max_cache_time, buf, length, offset );
    UNPACK_LIST_STRUCT( data, charging_rule_remove, GxChargingRuleRemove, buf, length, offset, unpackGxChargingRuleRemove );
    UNPACK_LIST_STRUCT( data, charging_rule_install, GxChargingRuleInstall, buf, length, offset, unpackGxChargingRuleInstall );
    UNPACK_STRUCT( data, charging_information, buf, length, offset, unpackGxChargingInformation );
    UNPACK_BASIC( data, online, buf, length, offset );
    UNPACK_BASIC( data, offline, buf, length, offset );
    UNPACK_LIST_STRUCT( data, qos_information, GxQosInformation, buf, length, offset, unpackGxQosInformation );
    UNPACK_BASIC( data, revalidation_time, buf, length, offset );
    UNPACK_STRUCT( data, default_eps_bearer_qos, buf, length, offset, unpackGxDefaultEpsBearerQos );
    UNPACK_STRUCT( data, default_qos_information, buf, length, offset, unpackGxDefaultQosInformation );
    UNPACK_BASIC( data, bearer_usage, buf, length, offset );
    UNPACK_LIST_STRUCT( data, usage_monitoring_information, GxUsageMonitoringInformation, buf, length, offset, unpackGxUsageMonitoringInformation );
    UNPACK_LIST_BASIC( data, csg_information_reporting, int32_t, buf, length, offset );
    UNPACK_STRUCT( data, user_csg_information, buf, length, offset, unpackGxUserCsgInformation );
    UNPACK_STRUCT( data, pra_install, buf, length, offset, unpackGxPraInstall );
    UNPACK_STRUCT( data, pra_remove, buf, length, offset, unpackGxPraRemove );
    UNPACK_STRUCT( data, presence_reporting_area_information, buf, length, offset, unpackGxPresenceReportingAreaInformation );
    UNPACK_BASIC( data, session_release_cause, buf, length, offset );
    UNPACK_BASIC( data, nbifom_support, buf, length, offset );
    UNPACK_BASIC( data, nbifom_mode, buf, length, offset );
    UNPACK_BASIC( data, default_access, buf, length, offset );
    UNPACK_BASIC( data, ran_rule_support, buf, length, offset );
    UNPACK_LIST_STRUCT( data, routing_rule_report, GxRoutingRuleReport, buf, length, offset, unpackGxRoutingRuleReport );
    UNPACK_LIST_STRUCT( data, conditional_policy_information, GxConditionalPolicyInformation, buf, length, offset, unpackGxConditionalPolicyInformation );
    UNPACK_BASIC( data, removal_of_access, buf, length, offset );
    UNPACK_BASIC( data, ip_can_type, buf, length, offset );
    UNPACK_OCTETSTRING( data, error_message, buf, length, offset );
    UNPACK_OCTETSTRING( data, error_reporting_host, buf, length, offset );
    UNPACK_STRUCT( data, failed_avp, buf, length, offset, unpackGxFailedAvp );
    UNPACK_LIST_STRUCT( data, proxy_info, GxProxyInfo, buf, length, offset, unpackGxProxyInfo );
    UNPACK_LIST_OCTETSTRING( data, route_record, GxRouteRecordOctetString, buf, length, offset );
    UNPACK_LIST_STRUCT( data, load, GxLoad, buf, length, offset, unpackGxLoad );

    return length == _offset;
}

/*
*
*       Fun:    gx_ccr_unpack
*
*       Desc:   Unpack the specified buffer into the Credit-Control-Request Message
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
int gx_ccr_unpack
(
    unsigned char *buf,
    GxCCR *data
)
{
    uint32_t length = *((uint32_t*)buf);
    uint32_t _offset = sizeof(uint32_t);
    uint32_t *offset = &_offset;

    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_OCTETSTRING( data, session_id, buf, length, offset );
    UNPACK_BASIC( data, drmp, buf, length, offset );
    UNPACK_BASIC( data, auth_application_id, buf, length, offset );
    UNPACK_OCTETSTRING( data, origin_host, buf, length, offset );
    UNPACK_OCTETSTRING( data, origin_realm, buf, length, offset );
    UNPACK_OCTETSTRING( data, destination_realm, buf, length, offset );
    UNPACK_OCTETSTRING( data, service_context_id, buf, length, offset );
    UNPACK_BASIC( data, cc_request_type, buf, length, offset );
    UNPACK_BASIC( data, cc_request_number, buf, length, offset );
    UNPACK_BASIC( data, credit_management_status, buf, length, offset );
    UNPACK_OCTETSTRING( data, destination_host, buf, length, offset );
    UNPACK_BASIC( data, origin_state_id, buf, length, offset );
    UNPACK_LIST_STRUCT( data, subscription_id, GxSubscriptionId, buf, length, offset, unpackGxSubscriptionId );
    UNPACK_STRUCT( data, oc_supported_features, buf, length, offset, unpackGxOcSupportedFeatures );
    UNPACK_LIST_STRUCT( data, supported_features, GxSupportedFeatures, buf, length, offset, unpackGxSupportedFeatures );
    UNPACK_STRUCT( data, tdf_information, buf, length, offset, unpackGxTdfInformation );
    UNPACK_BASIC( data, network_request_support, buf, length, offset );
    UNPACK_LIST_STRUCT( data, packet_filter_information, GxPacketFilterInformation, buf, length, offset, unpackGxPacketFilterInformation );
    UNPACK_BASIC( data, packet_filter_operation, buf, length, offset );
    UNPACK_OCTETSTRING( data, bearer_identifier, buf, length, offset );
    UNPACK_BASIC( data, bearer_operation, buf, length, offset );
    UNPACK_BASIC( data, dynamic_address_flag, buf, length, offset );
    UNPACK_BASIC( data, dynamic_address_flag_extension, buf, length, offset );
    UNPACK_BASIC( data, pdn_connection_charging_id, buf, length, offset );
    UNPACK_OCTETSTRING( data, framed_ip_address, buf, length, offset );
    UNPACK_OCTETSTRING( data, framed_ipv6_prefix, buf, length, offset );
    UNPACK_BASIC( data, ip_can_type, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp_rat_type, buf, length, offset );
    UNPACK_BASIC( data, an_trusted, buf, length, offset );
    UNPACK_BASIC( data, rat_type, buf, length, offset );
    UNPACK_BASIC( data, termination_cause, buf, length, offset );
    UNPACK_STRUCT( data, user_equipment_info, buf, length, offset, unpackGxUserEquipmentInfo );
    UNPACK_STRUCT( data, qos_information, buf, length, offset, unpackGxQosInformation );
    UNPACK_BASIC( data, qos_negotiation, buf, length, offset );
    UNPACK_BASIC( data, qos_upgrade, buf, length, offset );
    UNPACK_STRUCT( data, default_eps_bearer_qos, buf, length, offset, unpackGxDefaultEpsBearerQos );
    UNPACK_STRUCT( data, default_qos_information, buf, length, offset, unpackGxDefaultQosInformation );
    UNPACK_LIST_BASIC( data, an_gw_address, FdAddress, buf, length, offset );
    UNPACK_BASIC( data, an_gw_status, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp_sgsn_mcc_mnc, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp_sgsn_address, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp_sgsn_ipv6_address, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp_ggsn_address, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp_ggsn_ipv6_address, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp_selection_mode, buf, length, offset );
    UNPACK_OCTETSTRING( data, rai, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp_user_location_info, buf, length, offset );
    UNPACK_STRUCT( data, fixed_user_location_info, buf, length, offset, unpackGxFixedUserLocationInfo );
    UNPACK_BASIC( data, user_location_info_time, buf, length, offset );
    UNPACK_STRUCT( data, user_csg_information, buf, length, offset, unpackGxUserCsgInformation );
    UNPACK_OCTETSTRING( data, twan_identifier, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp_ms_timezone, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, ran_nas_release_cause, GxRanNasReleaseCauseOctetString, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp_charging_characteristics, buf, length, offset );
    UNPACK_OCTETSTRING( data, called_station_id, buf, length, offset );
    UNPACK_OCTETSTRING( data, pdn_connection_id, buf, length, offset );
    UNPACK_BASIC( data, bearer_usage, buf, length, offset );
    UNPACK_BASIC( data, online, buf, length, offset );
    UNPACK_BASIC( data, offline, buf, length, offset );
    UNPACK_LIST_STRUCT( data, tft_packet_filter_information, GxTftPacketFilterInformation, buf, length, offset, unpackGxTftPacketFilterInformation );
    UNPACK_LIST_STRUCT( data, charging_rule_report, GxChargingRuleReport, buf, length, offset, unpackGxChargingRuleReport );
    UNPACK_LIST_STRUCT( data, application_detection_information, GxApplicationDetectionInformation, buf, length, offset, unpackGxApplicationDetectionInformation );
    UNPACK_LIST_BASIC( data, event_trigger, int32_t, buf, length, offset );
    UNPACK_STRUCT( data, event_report_indication, buf, length, offset, unpackGxEventReportIndication );
    UNPACK_BASIC( data, access_network_charging_address, buf, length, offset );
    UNPACK_LIST_STRUCT( data, access_network_charging_identifier_gx, GxAccessNetworkChargingIdentifierGx, buf, length, offset, unpackGxAccessNetworkChargingIdentifierGx );
    UNPACK_LIST_STRUCT( data, coa_information, GxCoaInformation, buf, length, offset, unpackGxCoaInformation );
    UNPACK_LIST_STRUCT( data, usage_monitoring_information, GxUsageMonitoringInformation, buf, length, offset, unpackGxUsageMonitoringInformation );
    UNPACK_BASIC( data, nbifom_support, buf, length, offset );
    UNPACK_BASIC( data, nbifom_mode, buf, length, offset );
    UNPACK_BASIC( data, default_access, buf, length, offset );
    UNPACK_BASIC( data, origination_time_stamp, buf, length, offset );
    UNPACK_BASIC( data, maximum_wait_time, buf, length, offset );
    UNPACK_BASIC( data, access_availability_change_reason, buf, length, offset );
    UNPACK_STRUCT( data, routing_rule_install, buf, length, offset, unpackGxRoutingRuleInstall );
    UNPACK_STRUCT( data, routing_rule_remove, buf, length, offset, unpackGxRoutingRuleRemove );
    UNPACK_BASIC( data, henb_local_ip_address, buf, length, offset );
    UNPACK_BASIC( data, ue_local_ip_address, buf, length, offset );
    UNPACK_BASIC( data, udp_source_port, buf, length, offset );
    UNPACK_BASIC( data, tcp_source_port, buf, length, offset );
    UNPACK_LIST_STRUCT( data, presence_reporting_area_information, GxPresenceReportingAreaInformation, buf, length, offset, unpackGxPresenceReportingAreaInformation );
    UNPACK_OCTETSTRING( data, logical_access_id, buf, length, offset );
    UNPACK_OCTETSTRING( data, physical_access_id, buf, length, offset );
    UNPACK_LIST_STRUCT( data, proxy_info, GxProxyInfo, buf, length, offset, unpackGxProxyInfo );
    UNPACK_LIST_OCTETSTRING( data, route_record, GxRouteRecordOctetString, buf, length, offset );
    UNPACK_BASIC( data, tgpp_ps_data_off_status, buf, length, offset );

    return length == _offset;
}

/*******************************************************************************/
/* message length calculation functions                                        */
/*******************************************************************************/

/*
*
*       Fun:    calcLengthGxExperimentalResult
*
*       Desc:   Calculate the length for GxExperimentalResult
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Experimental-Result ::= <AVP Header: 297>
*              { Vendor-Id }
*              { Experimental-Result-Code }
*/
static uint32_t calcLengthGxExperimentalResult
(
    GxExperimentalResult *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, vendor_id );
    CALCLEN_BASIC( length, data, experimental_result_code );

    return length;
}

/*
*
*       Fun:    calcLengthGxPraRemove
*
*       Desc:   Calculate the length for GxPraRemove
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        PRA-Remove ::= <AVP Header: 2846>
*          *   [ Presence-Reporting-Area-Identifier ]
*          *   [ AVP ]
*/
static uint32_t calcLengthGxPraRemove
(
    GxPraRemove *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_LIST_OCTETSTRING( length, data, presence_reporting_area_identifier );

    return length;
}

/*
*
*       Fun:    calcLengthGxQosInformation
*
*       Desc:   Calculate the length for GxQosInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxQosInformation
(
    GxQosInformation *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, qos_class_identifier );
    CALCLEN_BASIC( length, data, max_requested_bandwidth_ul );
    CALCLEN_BASIC( length, data, max_requested_bandwidth_dl );
    CALCLEN_BASIC( length, data, extended_max_requested_bw_ul );
    CALCLEN_BASIC( length, data, extended_max_requested_bw_dl );
    CALCLEN_BASIC( length, data, guaranteed_bitrate_ul );
    CALCLEN_BASIC( length, data, guaranteed_bitrate_dl );
    CALCLEN_BASIC( length, data, extended_gbr_ul );
    CALCLEN_BASIC( length, data, extended_gbr_dl );
    CALCLEN_OCTETSTRING( length, data, bearer_identifier );
    CALCLEN_STRUCT( length, data, allocation_retention_priority, calcLengthGxAllocationRetentionPriority );
    CALCLEN_BASIC( length, data, apn_aggregate_max_bitrate_ul );
    CALCLEN_BASIC( length, data, apn_aggregate_max_bitrate_dl );
    CALCLEN_BASIC( length, data, extended_apn_ambr_ul );
    CALCLEN_BASIC( length, data, extended_apn_ambr_dl );
    CALCLEN_LIST_STRUCT( length, data, conditional_apn_aggregate_max_bitrate, calcLengthGxConditionalApnAggregateMaxBitrate );

    return length;
}

/*
*
*       Fun:    calcLengthGxConditionalPolicyInformation
*
*       Desc:   Calculate the length for GxConditionalPolicyInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxConditionalPolicyInformation
(
    GxConditionalPolicyInformation *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, execution_time );
    CALCLEN_STRUCT( length, data, default_eps_bearer_qos, calcLengthGxDefaultEpsBearerQos );
    CALCLEN_BASIC( length, data, apn_aggregate_max_bitrate_ul );
    CALCLEN_BASIC( length, data, apn_aggregate_max_bitrate_dl );
    CALCLEN_BASIC( length, data, extended_apn_ambr_ul );
    CALCLEN_BASIC( length, data, extended_apn_ambr_dl );
    CALCLEN_LIST_STRUCT( length, data, conditional_apn_aggregate_max_bitrate, calcLengthGxConditionalApnAggregateMaxBitrate );

    return length;
}

/*
*
*       Fun:    calcLengthGxPraInstall
*
*       Desc:   Calculate the length for GxPraInstall
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        PRA-Install ::= <AVP Header: 2845>
*          *   [ Presence-Reporting-Area-Information ]
*          *   [ AVP ]
*/
static uint32_t calcLengthGxPraInstall
(
    GxPraInstall *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_LIST_STRUCT( length, data, presence_reporting_area_information, calcLengthGxPresenceReportingAreaInformation );

    return length;
}

/*
*
*       Fun:    calcLengthGxAreaScope
*
*       Desc:   Calculate the length for GxAreaScope
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxAreaScope
(
    GxAreaScope *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_LIST_OCTETSTRING( length, data, cell_global_identity );
    CALCLEN_LIST_OCTETSTRING( length, data, e_utran_cell_global_identity );
    CALCLEN_LIST_OCTETSTRING( length, data, routing_area_identity );
    CALCLEN_LIST_OCTETSTRING( length, data, location_area_identity );
    CALCLEN_LIST_OCTETSTRING( length, data, tracking_area_identity );

    return length;
}

/*
*
*       Fun:    calcLengthGxFlowInformation
*
*       Desc:   Calculate the length for GxFlowInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxFlowInformation
(
    GxFlowInformation *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_OCTETSTRING( length, data, flow_description );
    CALCLEN_OCTETSTRING( length, data, packet_filter_identifier );
    CALCLEN_BASIC( length, data, packet_filter_usage );
    CALCLEN_OCTETSTRING( length, data, tos_traffic_class );
    CALCLEN_OCTETSTRING( length, data, security_parameter_index );
    CALCLEN_OCTETSTRING( length, data, flow_label );
    CALCLEN_BASIC( length, data, flow_direction );
    CALCLEN_OCTETSTRING( length, data, routing_rule_identifier );

    return length;
}

/*
*
*       Fun:    calcLengthGxTunnelInformation
*
*       Desc:   Calculate the length for GxTunnelInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Tunnel-Information ::= <AVP Header: 1038>
*              [ Tunnel-Header-Length ]
*              [ Tunnel-Header-Filter ]
*/
static uint32_t calcLengthGxTunnelInformation
(
    GxTunnelInformation *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, tunnel_header_length );
    CALCLEN_LIST_OCTETSTRING( length, data, tunnel_header_filter );

    return length;
}

/*
*
*       Fun:    calcLengthGxTftPacketFilterInformation
*
*       Desc:   Calculate the length for GxTftPacketFilterInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxTftPacketFilterInformation
(
    GxTftPacketFilterInformation *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, precedence );
    CALCLEN_OCTETSTRING( length, data, tft_filter );
    CALCLEN_OCTETSTRING( length, data, tos_traffic_class );
    CALCLEN_OCTETSTRING( length, data, security_parameter_index );
    CALCLEN_OCTETSTRING( length, data, flow_label );
    CALCLEN_BASIC( length, data, flow_direction );

    return length;
}

/*
*
*       Fun:    calcLengthGxMbsfnArea
*
*       Desc:   Calculate the length for GxMbsfnArea
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        MBSFN-Area ::= <AVP Header: 1694>
*              { MBSFN-Area-ID }
*              { Carrier-Frequency }
*          *   [ AVP ]
*/
static uint32_t calcLengthGxMbsfnArea
(
    GxMbsfnArea *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, mbsfn_area_id );
    CALCLEN_BASIC( length, data, carrier_frequency );

    return length;
}

/*
*
*       Fun:    calcLengthGxEventReportIndication
*
*       Desc:   Calculate the length for GxEventReportIndication
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxEventReportIndication
(
    GxEventReportIndication *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, an_trusted );
    CALCLEN_LIST_BASIC( length, data, event_trigger );
    CALCLEN_STRUCT( length, data, user_csg_information, calcLengthGxUserCsgInformation );
    CALCLEN_BASIC( length, data, ip_can_type );
    CALCLEN_LIST_BASIC( length, data, an_gw_address );
    CALCLEN_OCTETSTRING( length, data, tgpp_sgsn_address );
    CALCLEN_OCTETSTRING( length, data, tgpp_sgsn_ipv6_address );
    CALCLEN_OCTETSTRING( length, data, tgpp_sgsn_mcc_mnc );
    CALCLEN_OCTETSTRING( length, data, framed_ip_address );
    CALCLEN_BASIC( length, data, rat_type );
    CALCLEN_OCTETSTRING( length, data, rai );
    CALCLEN_OCTETSTRING( length, data, tgpp_user_location_info );
    CALCLEN_STRUCT( length, data, trace_data, calcLengthGxTraceData );
    CALCLEN_OCTETSTRING( length, data, trace_reference );
    CALCLEN_OCTETSTRING( length, data, tgpp2_bsid );
    CALCLEN_OCTETSTRING( length, data, tgpp_ms_timezone );
    CALCLEN_BASIC( length, data, routing_ip_address );
    CALCLEN_BASIC( length, data, ue_local_ip_address );
    CALCLEN_BASIC( length, data, henb_local_ip_address );
    CALCLEN_BASIC( length, data, udp_source_port );
    CALCLEN_STRUCT( length, data, presence_reporting_area_information, calcLengthGxPresenceReportingAreaInformation );

    return length;
}

/*
*
*       Fun:    calcLengthGxTdfInformation
*
*       Desc:   Calculate the length for GxTdfInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        TDF-Information ::= <AVP Header: 1087>
*              [ TDF-Destination-Realm ]
*              [ TDF-Destination-Host ]
*              [ TDF-IP-Address ]
*/
static uint32_t calcLengthGxTdfInformation
(
    GxTdfInformation *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_OCTETSTRING( length, data, tdf_destination_realm );
    CALCLEN_OCTETSTRING( length, data, tdf_destination_host );
    CALCLEN_BASIC( length, data, tdf_ip_address );

    return length;
}

/*
*
*       Fun:    calcLengthGxProxyInfo
*
*       Desc:   Calculate the length for GxProxyInfo
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Proxy-Info ::= <AVP Header: 284>
*              { Proxy-Host }
*              { Proxy-State }
*          *   [ AVP ]
*/
static uint32_t calcLengthGxProxyInfo
(
    GxProxyInfo *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_OCTETSTRING( length, data, proxy_host );
    CALCLEN_OCTETSTRING( length, data, proxy_state );

    return length;
}

/*
*
*       Fun:    calcLengthGxUsedServiceUnit
*
*       Desc:   Calculate the length for GxUsedServiceUnit
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxUsedServiceUnit
(
    GxUsedServiceUnit *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, reporting_reason );
    CALCLEN_BASIC( length, data, tariff_change_usage );
    CALCLEN_BASIC( length, data, cc_time );
    CALCLEN_STRUCT( length, data, cc_money, calcLengthGxCcMoney );
    CALCLEN_BASIC( length, data, cc_total_octets );
    CALCLEN_BASIC( length, data, cc_input_octets );
    CALCLEN_BASIC( length, data, cc_output_octets );
    CALCLEN_BASIC( length, data, cc_service_specific_units );
    CALCLEN_LIST_BASIC( length, data, event_charging_timestamp );

    return length;
}

/*
*
*       Fun:    calcLengthGxChargingRuleInstall
*
*       Desc:   Calculate the length for GxChargingRuleInstall
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxChargingRuleInstall
(
    GxChargingRuleInstall *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_LIST_STRUCT( length, data, charging_rule_definition, calcLengthGxChargingRuleDefinition );
    CALCLEN_LIST_OCTETSTRING( length, data, charging_rule_name );
    CALCLEN_LIST_OCTETSTRING( length, data, charging_rule_base_name );
    CALCLEN_OCTETSTRING( length, data, bearer_identifier );
    CALCLEN_BASIC( length, data, monitoring_flags );
    CALCLEN_BASIC( length, data, rule_activation_time );
    CALCLEN_BASIC( length, data, rule_deactivation_time );
    CALCLEN_BASIC( length, data, resource_allocation_notification );
    CALCLEN_BASIC( length, data, charging_correlation_indicator );
    CALCLEN_BASIC( length, data, ip_can_type );

    return length;
}

/*
*
*       Fun:    calcLengthGxChargingRuleDefinition
*
*       Desc:   Calculate the length for GxChargingRuleDefinition
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxChargingRuleDefinition
(
    GxChargingRuleDefinition *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_OCTETSTRING( length, data, charging_rule_name );
    CALCLEN_BASIC( length, data, service_identifier );
    CALCLEN_BASIC( length, data, rating_group );
    CALCLEN_LIST_STRUCT( length, data, flow_information, calcLengthGxFlowInformation );
    CALCLEN_BASIC( length, data, default_bearer_indication );
    CALCLEN_OCTETSTRING( length, data, tdf_application_identifier );
    CALCLEN_BASIC( length, data, flow_status );
    CALCLEN_STRUCT( length, data, qos_information, calcLengthGxQosInformation );
    CALCLEN_BASIC( length, data, ps_to_cs_session_continuity );
    CALCLEN_BASIC( length, data, reporting_level );
    CALCLEN_BASIC( length, data, online );
    CALCLEN_BASIC( length, data, offline );
    CALCLEN_BASIC( length, data, max_plr_dl );
    CALCLEN_BASIC( length, data, max_plr_ul );
    CALCLEN_BASIC( length, data, metering_method );
    CALCLEN_BASIC( length, data, precedence );
    CALCLEN_OCTETSTRING( length, data, af_charging_identifier );
    CALCLEN_LIST_STRUCT( length, data, flows, calcLengthGxFlows );
    CALCLEN_OCTETSTRING( length, data, monitoring_key );
    CALCLEN_STRUCT( length, data, redirect_information, calcLengthGxRedirectInformation );
    CALCLEN_BASIC( length, data, mute_notification );
    CALCLEN_BASIC( length, data, af_signalling_protocol );
    CALCLEN_OCTETSTRING( length, data, sponsor_identity );
    CALCLEN_OCTETSTRING( length, data, application_service_provider_identity );
    CALCLEN_LIST_BASIC( length, data, required_access_info );
    CALCLEN_BASIC( length, data, sharing_key_dl );
    CALCLEN_BASIC( length, data, sharing_key_ul );
    CALCLEN_OCTETSTRING( length, data, traffic_steering_policy_identifier_dl );
    CALCLEN_OCTETSTRING( length, data, traffic_steering_policy_identifier_ul );
    CALCLEN_BASIC( length, data, content_version );

    return length;
}

/*
*
*       Fun:    calcLengthGxFinalUnitIndication
*
*       Desc:   Calculate the length for GxFinalUnitIndication
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Final-Unit-Indication ::= <AVP Header: 430>
*              { Final-Unit-Action }
*          *   [ Restriction-Filter-Rule ]
*          *   [ Filter-Id ]
*              [ Redirect-Server ]
*/
static uint32_t calcLengthGxFinalUnitIndication
(
    GxFinalUnitIndication *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, final_unit_action );
    CALCLEN_LIST_OCTETSTRING( length, data, restriction_filter_rule );
    CALCLEN_LIST_OCTETSTRING( length, data, filter_id );
    CALCLEN_STRUCT( length, data, redirect_server, calcLengthGxRedirectServer );

    return length;
}

/*
*
*       Fun:    calcLengthGxUnitValue
*
*       Desc:   Calculate the length for GxUnitValue
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Unit-Value ::= <AVP Header: 445>
*              { Value-Digits }
*              [ Exponent ]
*/
static uint32_t calcLengthGxUnitValue
(
    GxUnitValue *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, value_digits );
    CALCLEN_BASIC( length, data, exponent );

    return length;
}

/*
*
*       Fun:    calcLengthGxPresenceReportingAreaInformation
*
*       Desc:   Calculate the length for GxPresenceReportingAreaInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxPresenceReportingAreaInformation
(
    GxPresenceReportingAreaInformation *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_OCTETSTRING( length, data, presence_reporting_area_identifier );
    CALCLEN_BASIC( length, data, presence_reporting_area_status );
    CALCLEN_OCTETSTRING( length, data, presence_reporting_area_elements_list );
    CALCLEN_BASIC( length, data, presence_reporting_area_node );

    return length;
}

/*
*
*       Fun:    calcLengthGxConditionalApnAggregateMaxBitrate
*
*       Desc:   Calculate the length for GxConditionalApnAggregateMaxBitrate
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxConditionalApnAggregateMaxBitrate
(
    GxConditionalApnAggregateMaxBitrate *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, apn_aggregate_max_bitrate_ul );
    CALCLEN_BASIC( length, data, apn_aggregate_max_bitrate_dl );
    CALCLEN_BASIC( length, data, extended_apn_ambr_ul );
    CALCLEN_BASIC( length, data, extended_apn_ambr_dl );
    CALCLEN_LIST_BASIC( length, data, ip_can_type );
    CALCLEN_LIST_BASIC( length, data, rat_type );

    return length;
}

/*
*
*       Fun:    calcLengthGxAccessNetworkChargingIdentifierGx
*
*       Desc:   Calculate the length for GxAccessNetworkChargingIdentifierGx
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxAccessNetworkChargingIdentifierGx
(
    GxAccessNetworkChargingIdentifierGx *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_OCTETSTRING( length, data, access_network_charging_identifier_value );
    CALCLEN_LIST_OCTETSTRING( length, data, charging_rule_base_name );
    CALCLEN_LIST_OCTETSTRING( length, data, charging_rule_name );
    CALCLEN_BASIC( length, data, ip_can_session_charging_scope );

    return length;
}

/*
*
*       Fun:    calcLengthGxOcOlr
*
*       Desc:   Calculate the length for GxOcOlr
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxOcOlr
(
    GxOcOlr *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, oc_sequence_number );
    CALCLEN_BASIC( length, data, oc_report_type );
    CALCLEN_BASIC( length, data, oc_reduction_percentage );
    CALCLEN_BASIC( length, data, oc_validity_duration );

    return length;
}

/*
*
*       Fun:    calcLengthGxRoutingRuleInstall
*
*       Desc:   Calculate the length for GxRoutingRuleInstall
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Routing-Rule-Install ::= <AVP Header: 1081>
*          *   [ Routing-Rule-Definition ]
*          *   [ AVP ]
*/
static uint32_t calcLengthGxRoutingRuleInstall
(
    GxRoutingRuleInstall *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_LIST_STRUCT( length, data, routing_rule_definition, calcLengthGxRoutingRuleDefinition );

    return length;
}

/*
*
*       Fun:    calcLengthGxTraceData
*
*       Desc:   Calculate the length for GxTraceData
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxTraceData
(
    GxTraceData *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_OCTETSTRING( length, data, trace_reference );
    CALCLEN_BASIC( length, data, trace_depth );
    CALCLEN_OCTETSTRING( length, data, trace_ne_type_list );
    CALCLEN_OCTETSTRING( length, data, trace_interface_list );
    CALCLEN_OCTETSTRING( length, data, trace_event_list );
    CALCLEN_OCTETSTRING( length, data, omc_id );
    CALCLEN_BASIC( length, data, trace_collection_entity );
    CALCLEN_STRUCT( length, data, mdt_configuration, calcLengthGxMdtConfiguration );

    return length;
}

/*
*
*       Fun:    calcLengthGxRoutingRuleDefinition
*
*       Desc:   Calculate the length for GxRoutingRuleDefinition
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxRoutingRuleDefinition
(
    GxRoutingRuleDefinition *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_OCTETSTRING( length, data, routing_rule_identifier );
    CALCLEN_LIST_STRUCT( length, data, routing_filter, calcLengthGxRoutingFilter );
    CALCLEN_BASIC( length, data, precedence );
    CALCLEN_BASIC( length, data, routing_ip_address );
    CALCLEN_BASIC( length, data, ip_can_type );

    return length;
}

/*
*
*       Fun:    calcLengthGxMdtConfiguration
*
*       Desc:   Calculate the length for GxMdtConfiguration
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxMdtConfiguration
(
    GxMdtConfiguration *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, job_type );
    CALCLEN_STRUCT( length, data, area_scope, calcLengthGxAreaScope );
    CALCLEN_BASIC( length, data, list_of_measurements );
    CALCLEN_BASIC( length, data, reporting_trigger );
    CALCLEN_BASIC( length, data, report_interval );
    CALCLEN_BASIC( length, data, report_amount );
    CALCLEN_BASIC( length, data, event_threshold_rsrp );
    CALCLEN_BASIC( length, data, event_threshold_rsrq );
    CALCLEN_BASIC( length, data, logging_interval );
    CALCLEN_BASIC( length, data, logging_duration );
    CALCLEN_BASIC( length, data, measurement_period_lte );
    CALCLEN_BASIC( length, data, measurement_period_umts );
    CALCLEN_BASIC( length, data, collection_period_rrm_lte );
    CALCLEN_BASIC( length, data, collection_period_rrm_umts );
    CALCLEN_OCTETSTRING( length, data, positioning_method );
    CALCLEN_OCTETSTRING( length, data, measurement_quantity );
    CALCLEN_BASIC( length, data, event_threshold_event_1f );
    CALCLEN_BASIC( length, data, event_threshold_event_1i );
    CALCLEN_LIST_OCTETSTRING( length, data, mdt_allowed_plmn_id );
    CALCLEN_LIST_STRUCT( length, data, mbsfn_area, calcLengthGxMbsfnArea );

    return length;
}

/*
*
*       Fun:    calcLengthGxChargingRuleRemove
*
*       Desc:   Calculate the length for GxChargingRuleRemove
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxChargingRuleRemove
(
    GxChargingRuleRemove *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_LIST_OCTETSTRING( length, data, charging_rule_name );
    CALCLEN_LIST_OCTETSTRING( length, data, charging_rule_base_name );
    CALCLEN_LIST_BASIC( length, data, required_access_info );
    CALCLEN_BASIC( length, data, resource_release_notification );

    return length;
}

/*
*
*       Fun:    calcLengthGxAllocationRetentionPriority
*
*       Desc:   Calculate the length for GxAllocationRetentionPriority
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Allocation-Retention-Priority ::= <AVP Header: 1034>
*              { Priority-Level }
*              [ Pre-emption-Capability ]
*              [ Pre-emption-Vulnerability ]
*/
static uint32_t calcLengthGxAllocationRetentionPriority
(
    GxAllocationRetentionPriority *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, priority_level );
    CALCLEN_BASIC( length, data, pre_emption_capability );
    CALCLEN_BASIC( length, data, pre_emption_vulnerability );

    return length;
}

/*
*
*       Fun:    calcLengthGxDefaultEpsBearerQos
*
*       Desc:   Calculate the length for GxDefaultEpsBearerQos
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Default-EPS-Bearer-QoS ::= <AVP Header: 1049>
*              [ QoS-Class-Identifier ]
*              [ Allocation-Retention-Priority ]
*          *   [ AVP ]
*/
static uint32_t calcLengthGxDefaultEpsBearerQos
(
    GxDefaultEpsBearerQos *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, qos_class_identifier );
    CALCLEN_STRUCT( length, data, allocation_retention_priority, calcLengthGxAllocationRetentionPriority );

    return length;
}

/*
*
*       Fun:    calcLengthGxRoutingRuleReport
*
*       Desc:   Calculate the length for GxRoutingRuleReport
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Routing-Rule-Report ::= <AVP Header: 2835>
*          *   [ Routing-Rule-Identifier ]
*              [ PCC-Rule-Status ]
*              [ Routing-Rule-Failure-Code ]
*          *   [ AVP ]
*/
static uint32_t calcLengthGxRoutingRuleReport
(
    GxRoutingRuleReport *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_LIST_OCTETSTRING( length, data, routing_rule_identifier );
    CALCLEN_BASIC( length, data, pcc_rule_status );
    CALCLEN_BASIC( length, data, routing_rule_failure_code );

    return length;
}

/*
*
*       Fun:    calcLengthGxUserEquipmentInfo
*
*       Desc:   Calculate the length for GxUserEquipmentInfo
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        User-Equipment-Info ::= <AVP Header: 458>
*              { User-Equipment-Info-Type }
*              { User-Equipment-Info-Value }
*/
static uint32_t calcLengthGxUserEquipmentInfo
(
    GxUserEquipmentInfo *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, user_equipment_info_type );
    CALCLEN_OCTETSTRING( length, data, user_equipment_info_value );

    return length;
}

/*
*
*       Fun:    calcLengthGxSupportedFeatures
*
*       Desc:   Calculate the length for GxSupportedFeatures
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Supported-Features ::= <AVP Header: 628>
*              { Vendor-Id }
*              { Feature-List-ID }
*              { Feature-List }
*          *   [ AVP ]
*/
static uint32_t calcLengthGxSupportedFeatures
(
    GxSupportedFeatures *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, vendor_id );
    CALCLEN_BASIC( length, data, feature_list_id );
    CALCLEN_BASIC( length, data, feature_list );

    return length;
}

/*
*
*       Fun:    calcLengthGxFixedUserLocationInfo
*
*       Desc:   Calculate the length for GxFixedUserLocationInfo
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxFixedUserLocationInfo
(
    GxFixedUserLocationInfo *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_OCTETSTRING( length, data, ssid );
    CALCLEN_OCTETSTRING( length, data, bssid );
    CALCLEN_OCTETSTRING( length, data, logical_access_id );
    CALCLEN_OCTETSTRING( length, data, physical_access_id );

    return length;
}

/*
*
*       Fun:    calcLengthGxDefaultQosInformation
*
*       Desc:   Calculate the length for GxDefaultQosInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxDefaultQosInformation
(
    GxDefaultQosInformation *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, qos_class_identifier );
    CALCLEN_BASIC( length, data, max_requested_bandwidth_ul );
    CALCLEN_BASIC( length, data, max_requested_bandwidth_dl );
    CALCLEN_OCTETSTRING( length, data, default_qos_name );

    return length;
}

/*
*
*       Fun:    calcLengthGxLoad
*
*       Desc:   Calculate the length for GxLoad
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Load ::= <AVP Header: 650>
*              [ Load-Type ]
*              [ Load-Value ]
*              [ SourceID ]
*          *   [ AVP ]
*/
static uint32_t calcLengthGxLoad
(
    GxLoad *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, load_type );
    CALCLEN_BASIC( length, data, load_value );
    CALCLEN_OCTETSTRING( length, data, sourceid );

    return length;
}

/*
*
*       Fun:    calcLengthGxRedirectServer
*
*       Desc:   Calculate the length for GxRedirectServer
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Redirect-Server ::= <AVP Header: 434>
*              { Redirect-Address-Type }
*              { Redirect-Server-Address }
*/
static uint32_t calcLengthGxRedirectServer
(
    GxRedirectServer *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, redirect_address_type );
    CALCLEN_OCTETSTRING( length, data, redirect_server_address );

    return length;
}

/*
*
*       Fun:    calcLengthGxOcSupportedFeatures
*
*       Desc:   Calculate the length for GxOcSupportedFeatures
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        OC-Supported-Features ::= <AVP Header: 621>
*              [ OC-Feature-Vector ]
*          *   [ AVP ]
*/
static uint32_t calcLengthGxOcSupportedFeatures
(
    GxOcSupportedFeatures *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, oc_feature_vector );

    return length;
}

/*
*
*       Fun:    calcLengthGxPacketFilterInformation
*
*       Desc:   Calculate the length for GxPacketFilterInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxPacketFilterInformation
(
    GxPacketFilterInformation *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_OCTETSTRING( length, data, packet_filter_identifier );
    CALCLEN_BASIC( length, data, precedence );
    CALCLEN_OCTETSTRING( length, data, packet_filter_content );
    CALCLEN_OCTETSTRING( length, data, tos_traffic_class );
    CALCLEN_OCTETSTRING( length, data, security_parameter_index );
    CALCLEN_OCTETSTRING( length, data, flow_label );
    CALCLEN_BASIC( length, data, flow_direction );

    return length;
}

/*
*
*       Fun:    calcLengthGxSubscriptionId
*
*       Desc:   Calculate the length for GxSubscriptionId
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Subscription-Id ::= <AVP Header: 443>
*              [ Subscription-Id-Type ]
*              [ Subscription-Id-Data ]
*/
static uint32_t calcLengthGxSubscriptionId
(
    GxSubscriptionId *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, subscription_id_type );
    CALCLEN_OCTETSTRING( length, data, subscription_id_data );

    return length;
}

/*
*
*       Fun:    calcLengthGxChargingInformation
*
*       Desc:   Calculate the length for GxChargingInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxChargingInformation
(
    GxChargingInformation *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_OCTETSTRING( length, data, primary_event_charging_function_name );
    CALCLEN_OCTETSTRING( length, data, secondary_event_charging_function_name );
    CALCLEN_OCTETSTRING( length, data, primary_charging_collection_function_name );
    CALCLEN_OCTETSTRING( length, data, secondary_charging_collection_function_name );

    return length;
}

/*
*
*       Fun:    calcLengthGxUsageMonitoringInformation
*
*       Desc:   Calculate the length for GxUsageMonitoringInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxUsageMonitoringInformation
(
    GxUsageMonitoringInformation *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_OCTETSTRING( length, data, monitoring_key );
    CALCLEN_LIST_STRUCT( length, data, granted_service_unit, calcLengthGxGrantedServiceUnit );
    CALCLEN_LIST_STRUCT( length, data, used_service_unit, calcLengthGxUsedServiceUnit );
    CALCLEN_BASIC( length, data, quota_consumption_time );
    CALCLEN_BASIC( length, data, usage_monitoring_level );
    CALCLEN_BASIC( length, data, usage_monitoring_report );
    CALCLEN_BASIC( length, data, usage_monitoring_support );

    return length;
}

/*
*
*       Fun:    calcLengthGxChargingRuleReport
*
*       Desc:   Calculate the length for GxChargingRuleReport
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxChargingRuleReport
(
    GxChargingRuleReport *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_LIST_OCTETSTRING( length, data, charging_rule_name );
    CALCLEN_LIST_OCTETSTRING( length, data, charging_rule_base_name );
    CALCLEN_OCTETSTRING( length, data, bearer_identifier );
    CALCLEN_BASIC( length, data, pcc_rule_status );
    CALCLEN_BASIC( length, data, rule_failure_code );
    CALCLEN_STRUCT( length, data, final_unit_indication, calcLengthGxFinalUnitIndication );
    CALCLEN_LIST_OCTETSTRING( length, data, ran_nas_release_cause );
    CALCLEN_LIST_BASIC( length, data, content_version );

    return length;
}

/*
*
*       Fun:    calcLengthGxRedirectInformation
*
*       Desc:   Calculate the length for GxRedirectInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Redirect-Information ::= <AVP Header: 1085>
*              [ Redirect-Support ]
*              [ Redirect-Address-Type ]
*              [ Redirect-Server-Address ]
*          *   [ AVP ]
*/
static uint32_t calcLengthGxRedirectInformation
(
    GxRedirectInformation *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, redirect_support );
    CALCLEN_BASIC( length, data, redirect_address_type );
    CALCLEN_OCTETSTRING( length, data, redirect_server_address );

    return length;
}

/*
*
*       Fun:    calcLengthGxFailedAvp
*
*       Desc:   Calculate the length for GxFailedAvp
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Failed-AVP ::= <AVP Header: 279>
*         1*   { AVP }
*/
static uint32_t calcLengthGxFailedAvp
(
    GxFailedAvp *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );

    return length;
}

/*
*
*       Fun:    calcLengthGxRoutingRuleRemove
*
*       Desc:   Calculate the length for GxRoutingRuleRemove
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Routing-Rule-Remove ::= <AVP Header: 1075>
*          *   [ Routing-Rule-Identifier ]
*          *   [ AVP ]
*/
static uint32_t calcLengthGxRoutingRuleRemove
(
    GxRoutingRuleRemove *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_LIST_OCTETSTRING( length, data, routing_rule_identifier );

    return length;
}

/*
*
*       Fun:    calcLengthGxRoutingFilter
*
*       Desc:   Calculate the length for GxRoutingFilter
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxRoutingFilter
(
    GxRoutingFilter *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_OCTETSTRING( length, data, flow_description );
    CALCLEN_BASIC( length, data, flow_direction );
    CALCLEN_OCTETSTRING( length, data, tos_traffic_class );
    CALCLEN_OCTETSTRING( length, data, security_parameter_index );
    CALCLEN_OCTETSTRING( length, data, flow_label );

    return length;
}

/*
*
*       Fun:    calcLengthGxCoaInformation
*
*       Desc:   Calculate the length for GxCoaInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        CoA-Information ::= <AVP Header: 1039>
*              { Tunnel-Information }
*              { CoA-IP-Address }
*          *   [ AVP ]
*/
static uint32_t calcLengthGxCoaInformation
(
    GxCoaInformation *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_STRUCT( length, data, tunnel_information, calcLengthGxTunnelInformation );
    CALCLEN_BASIC( length, data, coa_ip_address );

    return length;
}

/*
*
*       Fun:    calcLengthGxGrantedServiceUnit
*
*       Desc:   Calculate the length for GxGrantedServiceUnit
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxGrantedServiceUnit
(
    GxGrantedServiceUnit *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, tariff_time_change );
    CALCLEN_BASIC( length, data, cc_time );
    CALCLEN_STRUCT( length, data, cc_money, calcLengthGxCcMoney );
    CALCLEN_BASIC( length, data, cc_total_octets );
    CALCLEN_BASIC( length, data, cc_input_octets );
    CALCLEN_BASIC( length, data, cc_output_octets );
    CALCLEN_BASIC( length, data, cc_service_specific_units );

    return length;
}

/*
*
*       Fun:    calcLengthGxCcMoney
*
*       Desc:   Calculate the length for GxCcMoney
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        CC-Money ::= <AVP Header: 413>
*              { Unit-Value }
*              [ Currency-Code ]
*/
static uint32_t calcLengthGxCcMoney
(
    GxCcMoney *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_STRUCT( length, data, unit_value, calcLengthGxUnitValue );
    CALCLEN_BASIC( length, data, currency_code );

    return length;
}

/*
*
*       Fun:    calcLengthGxApplicationDetectionInformation
*
*       Desc:   Calculate the length for GxApplicationDetectionInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Application-Detection-Information ::= <AVP Header: 1098>
*              { TDF-Application-Identifier }
*              [ TDF-Application-Instance-Identifier ]
*          *   [ Flow-Information ]
*          *   [ AVP ]
*/
static uint32_t calcLengthGxApplicationDetectionInformation
(
    GxApplicationDetectionInformation *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_OCTETSTRING( length, data, tdf_application_identifier );
    CALCLEN_OCTETSTRING( length, data, tdf_application_instance_identifier );
    CALCLEN_LIST_STRUCT( length, data, flow_information, calcLengthGxFlowInformation );

    return length;
}

/*
*
*       Fun:    calcLengthGxFlows
*
*       Desc:   Calculate the length for GxFlows
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static uint32_t calcLengthGxFlows
(
    GxFlows *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, media_component_number );
    CALCLEN_LIST_BASIC( length, data, flow_number );
    CALCLEN_LIST_BASIC( length, data, content_version );
    CALCLEN_BASIC( length, data, final_unit_action );
    CALCLEN_BASIC( length, data, media_component_status );

    return length;
}

/*
*
*       Fun:    calcLengthGxUserCsgInformation
*
*       Desc:   Calculate the length for GxUserCsgInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        User-CSG-Information ::= <AVP Header: 2319>
*              { CSG-Id }
*              { CSG-Access-Mode }
*              [ CSG-Membership-Indication ]
*/
static uint32_t calcLengthGxUserCsgInformation
(
    GxUserCsgInformation *data
)
{
    uint32_t length = 0;

    CALCLEN_PRESENCE( length, data, presence );
    CALCLEN_BASIC( length, data, csg_id );
    CALCLEN_BASIC( length, data, csg_access_mode );
    CALCLEN_BASIC( length, data, csg_membership_indication );

    return length;
}

/*******************************************************************************/
/* structure pack functions                                                    */
/*******************************************************************************/

/*
*
*       Fun:    packGxExperimentalResult
*
*       Desc:   Pack the contents of the GxExperimentalResult structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Experimental-Result ::= <AVP Header: 297>
*              { Vendor-Id }
*              { Experimental-Result-Code }
*/
static int packGxExperimentalResult
(
    GxExperimentalResult *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, vendor_id, buf, buflen, offset );
    PACK_BASIC( data, experimental_result_code, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxPraRemove
*
*       Desc:   Pack the contents of the GxPraRemove structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        PRA-Remove ::= <AVP Header: 2846>
*          *   [ Presence-Reporting-Area-Identifier ]
*          *   [ AVP ]
*/
static int packGxPraRemove
(
    GxPraRemove *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, presence_reporting_area_identifier, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxQosInformation
*
*       Desc:   Pack the contents of the GxQosInformation structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxQosInformation
(
    GxQosInformation *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, qos_class_identifier, buf, buflen, offset );
    PACK_BASIC( data, max_requested_bandwidth_ul, buf, buflen, offset );
    PACK_BASIC( data, max_requested_bandwidth_dl, buf, buflen, offset );
    PACK_BASIC( data, extended_max_requested_bw_ul, buf, buflen, offset );
    PACK_BASIC( data, extended_max_requested_bw_dl, buf, buflen, offset );
    PACK_BASIC( data, guaranteed_bitrate_ul, buf, buflen, offset );
    PACK_BASIC( data, guaranteed_bitrate_dl, buf, buflen, offset );
    PACK_BASIC( data, extended_gbr_ul, buf, buflen, offset );
    PACK_BASIC( data, extended_gbr_dl, buf, buflen, offset );
    PACK_OCTETSTRING( data, bearer_identifier, buf, buflen, offset );
    PACK_STRUCT( data, allocation_retention_priority, buf, buflen, offset, packGxAllocationRetentionPriority );
    PACK_BASIC( data, apn_aggregate_max_bitrate_ul, buf, buflen, offset );
    PACK_BASIC( data, apn_aggregate_max_bitrate_dl, buf, buflen, offset );
    PACK_BASIC( data, extended_apn_ambr_ul, buf, buflen, offset );
    PACK_BASIC( data, extended_apn_ambr_dl, buf, buflen, offset );
    PACK_LIST_STRUCT( data, conditional_apn_aggregate_max_bitrate, buf, buflen, offset, packGxConditionalApnAggregateMaxBitrate );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxConditionalPolicyInformation
*
*       Desc:   Pack the contents of the GxConditionalPolicyInformation structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxConditionalPolicyInformation
(
    GxConditionalPolicyInformation *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, execution_time, buf, buflen, offset );
    PACK_STRUCT( data, default_eps_bearer_qos, buf, buflen, offset, packGxDefaultEpsBearerQos );
    PACK_BASIC( data, apn_aggregate_max_bitrate_ul, buf, buflen, offset );
    PACK_BASIC( data, apn_aggregate_max_bitrate_dl, buf, buflen, offset );
    PACK_BASIC( data, extended_apn_ambr_ul, buf, buflen, offset );
    PACK_BASIC( data, extended_apn_ambr_dl, buf, buflen, offset );
    PACK_LIST_STRUCT( data, conditional_apn_aggregate_max_bitrate, buf, buflen, offset, packGxConditionalApnAggregateMaxBitrate );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxPraInstall
*
*       Desc:   Pack the contents of the GxPraInstall structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        PRA-Install ::= <AVP Header: 2845>
*          *   [ Presence-Reporting-Area-Information ]
*          *   [ AVP ]
*/
static int packGxPraInstall
(
    GxPraInstall *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_LIST_STRUCT( data, presence_reporting_area_information, buf, buflen, offset, packGxPresenceReportingAreaInformation );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxAreaScope
*
*       Desc:   Pack the contents of the GxAreaScope structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxAreaScope
(
    GxAreaScope *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, cell_global_identity, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, e_utran_cell_global_identity, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, routing_area_identity, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, location_area_identity, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, tracking_area_identity, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxFlowInformation
*
*       Desc:   Pack the contents of the GxFlowInformation structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxFlowInformation
(
    GxFlowInformation *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_OCTETSTRING( data, flow_description, buf, buflen, offset );
    PACK_OCTETSTRING( data, packet_filter_identifier, buf, buflen, offset );
    PACK_BASIC( data, packet_filter_usage, buf, buflen, offset );
    PACK_OCTETSTRING( data, tos_traffic_class, buf, buflen, offset );
    PACK_OCTETSTRING( data, security_parameter_index, buf, buflen, offset );
    PACK_OCTETSTRING( data, flow_label, buf, buflen, offset );
    PACK_BASIC( data, flow_direction, buf, buflen, offset );
    PACK_OCTETSTRING( data, routing_rule_identifier, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxTunnelInformation
*
*       Desc:   Pack the contents of the GxTunnelInformation structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Tunnel-Information ::= <AVP Header: 1038>
*              [ Tunnel-Header-Length ]
*              [ Tunnel-Header-Filter ]
*/
static int packGxTunnelInformation
(
    GxTunnelInformation *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, tunnel_header_length, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, tunnel_header_filter, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxTftPacketFilterInformation
*
*       Desc:   Pack the contents of the GxTftPacketFilterInformation structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxTftPacketFilterInformation
(
    GxTftPacketFilterInformation *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, precedence, buf, buflen, offset );
    PACK_OCTETSTRING( data, tft_filter, buf, buflen, offset );
    PACK_OCTETSTRING( data, tos_traffic_class, buf, buflen, offset );
    PACK_OCTETSTRING( data, security_parameter_index, buf, buflen, offset );
    PACK_OCTETSTRING( data, flow_label, buf, buflen, offset );
    PACK_BASIC( data, flow_direction, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxMbsfnArea
*
*       Desc:   Pack the contents of the GxMbsfnArea structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        MBSFN-Area ::= <AVP Header: 1694>
*              { MBSFN-Area-ID }
*              { Carrier-Frequency }
*          *   [ AVP ]
*/
static int packGxMbsfnArea
(
    GxMbsfnArea *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, mbsfn_area_id, buf, buflen, offset );
    PACK_BASIC( data, carrier_frequency, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxEventReportIndication
*
*       Desc:   Pack the contents of the GxEventReportIndication structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxEventReportIndication
(
    GxEventReportIndication *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, an_trusted, buf, buflen, offset );
    PACK_LIST_BASIC( data, event_trigger, buf, buflen, offset );
    PACK_STRUCT( data, user_csg_information, buf, buflen, offset, packGxUserCsgInformation );
    PACK_BASIC( data, ip_can_type, buf, buflen, offset );
    PACK_LIST_BASIC( data, an_gw_address, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp_sgsn_address, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp_sgsn_ipv6_address, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp_sgsn_mcc_mnc, buf, buflen, offset );
    PACK_OCTETSTRING( data, framed_ip_address, buf, buflen, offset );
    PACK_BASIC( data, rat_type, buf, buflen, offset );
    PACK_OCTETSTRING( data, rai, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp_user_location_info, buf, buflen, offset );
    PACK_STRUCT( data, trace_data, buf, buflen, offset, packGxTraceData );
    PACK_OCTETSTRING( data, trace_reference, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp2_bsid, buf, buflen, offset );
    PACK_OCTETSTRING( data, tgpp_ms_timezone, buf, buflen, offset );
    PACK_BASIC( data, routing_ip_address, buf, buflen, offset );
    PACK_BASIC( data, ue_local_ip_address, buf, buflen, offset );
    PACK_BASIC( data, henb_local_ip_address, buf, buflen, offset );
    PACK_BASIC( data, udp_source_port, buf, buflen, offset );
    PACK_STRUCT( data, presence_reporting_area_information, buf, buflen, offset, packGxPresenceReportingAreaInformation );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxTdfInformation
*
*       Desc:   Pack the contents of the GxTdfInformation structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        TDF-Information ::= <AVP Header: 1087>
*              [ TDF-Destination-Realm ]
*              [ TDF-Destination-Host ]
*              [ TDF-IP-Address ]
*/
static int packGxTdfInformation
(
    GxTdfInformation *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_OCTETSTRING( data, tdf_destination_realm, buf, buflen, offset );
    PACK_OCTETSTRING( data, tdf_destination_host, buf, buflen, offset );
    PACK_BASIC( data, tdf_ip_address, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxProxyInfo
*
*       Desc:   Pack the contents of the GxProxyInfo structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Proxy-Info ::= <AVP Header: 284>
*              { Proxy-Host }
*              { Proxy-State }
*          *   [ AVP ]
*/
static int packGxProxyInfo
(
    GxProxyInfo *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_OCTETSTRING( data, proxy_host, buf, buflen, offset );
    PACK_OCTETSTRING( data, proxy_state, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxUsedServiceUnit
*
*       Desc:   Pack the contents of the GxUsedServiceUnit structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxUsedServiceUnit
(
    GxUsedServiceUnit *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, reporting_reason, buf, buflen, offset );
    PACK_BASIC( data, tariff_change_usage, buf, buflen, offset );
    PACK_BASIC( data, cc_time, buf, buflen, offset );
    PACK_STRUCT( data, cc_money, buf, buflen, offset, packGxCcMoney );
    PACK_BASIC( data, cc_total_octets, buf, buflen, offset );
    PACK_BASIC( data, cc_input_octets, buf, buflen, offset );
    PACK_BASIC( data, cc_output_octets, buf, buflen, offset );
    PACK_BASIC( data, cc_service_specific_units, buf, buflen, offset );
    PACK_LIST_BASIC( data, event_charging_timestamp, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxChargingRuleInstall
*
*       Desc:   Pack the contents of the GxChargingRuleInstall structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxChargingRuleInstall
(
    GxChargingRuleInstall *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_LIST_STRUCT( data, charging_rule_definition, buf, buflen, offset, packGxChargingRuleDefinition );
    PACK_LIST_OCTETSTRING( data, charging_rule_name, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, charging_rule_base_name, buf, buflen, offset );
    PACK_OCTETSTRING( data, bearer_identifier, buf, buflen, offset );
    PACK_BASIC( data, monitoring_flags, buf, buflen, offset );
    PACK_BASIC( data, rule_activation_time, buf, buflen, offset );
    PACK_BASIC( data, rule_deactivation_time, buf, buflen, offset );
    PACK_BASIC( data, resource_allocation_notification, buf, buflen, offset );
    PACK_BASIC( data, charging_correlation_indicator, buf, buflen, offset );
    PACK_BASIC( data, ip_can_type, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxChargingRuleDefinition
*
*       Desc:   Pack the contents of the GxChargingRuleDefinition structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxChargingRuleDefinition
(
    GxChargingRuleDefinition *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_OCTETSTRING( data, charging_rule_name, buf, buflen, offset );
    PACK_BASIC( data, service_identifier, buf, buflen, offset );
    PACK_BASIC( data, rating_group, buf, buflen, offset );
    PACK_LIST_STRUCT( data, flow_information, buf, buflen, offset, packGxFlowInformation );
    PACK_BASIC( data, default_bearer_indication, buf, buflen, offset );
    PACK_OCTETSTRING( data, tdf_application_identifier, buf, buflen, offset );
    PACK_BASIC( data, flow_status, buf, buflen, offset );
    PACK_STRUCT( data, qos_information, buf, buflen, offset, packGxQosInformation );
    PACK_BASIC( data, ps_to_cs_session_continuity, buf, buflen, offset );
    PACK_BASIC( data, reporting_level, buf, buflen, offset );
    PACK_BASIC( data, online, buf, buflen, offset );
    PACK_BASIC( data, offline, buf, buflen, offset );
    PACK_BASIC( data, max_plr_dl, buf, buflen, offset );
    PACK_BASIC( data, max_plr_ul, buf, buflen, offset );
    PACK_BASIC( data, metering_method, buf, buflen, offset );
    PACK_BASIC( data, precedence, buf, buflen, offset );
    PACK_OCTETSTRING( data, af_charging_identifier, buf, buflen, offset );
    PACK_LIST_STRUCT( data, flows, buf, buflen, offset, packGxFlows );
    PACK_OCTETSTRING( data, monitoring_key, buf, buflen, offset );
    PACK_STRUCT( data, redirect_information, buf, buflen, offset, packGxRedirectInformation );
    PACK_BASIC( data, mute_notification, buf, buflen, offset );
    PACK_BASIC( data, af_signalling_protocol, buf, buflen, offset );
    PACK_OCTETSTRING( data, sponsor_identity, buf, buflen, offset );
    PACK_OCTETSTRING( data, application_service_provider_identity, buf, buflen, offset );
    PACK_LIST_BASIC( data, required_access_info, buf, buflen, offset );
    PACK_BASIC( data, sharing_key_dl, buf, buflen, offset );
    PACK_BASIC( data, sharing_key_ul, buf, buflen, offset );
    PACK_OCTETSTRING( data, traffic_steering_policy_identifier_dl, buf, buflen, offset );
    PACK_OCTETSTRING( data, traffic_steering_policy_identifier_ul, buf, buflen, offset );
    PACK_BASIC( data, content_version, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxFinalUnitIndication
*
*       Desc:   Pack the contents of the GxFinalUnitIndication structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Final-Unit-Indication ::= <AVP Header: 430>
*              { Final-Unit-Action }
*          *   [ Restriction-Filter-Rule ]
*          *   [ Filter-Id ]
*              [ Redirect-Server ]
*/
static int packGxFinalUnitIndication
(
    GxFinalUnitIndication *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, final_unit_action, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, restriction_filter_rule, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, filter_id, buf, buflen, offset );
    PACK_STRUCT( data, redirect_server, buf, buflen, offset, packGxRedirectServer );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxUnitValue
*
*       Desc:   Pack the contents of the GxUnitValue structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Unit-Value ::= <AVP Header: 445>
*              { Value-Digits }
*              [ Exponent ]
*/
static int packGxUnitValue
(
    GxUnitValue *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, value_digits, buf, buflen, offset );
    PACK_BASIC( data, exponent, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxPresenceReportingAreaInformation
*
*       Desc:   Pack the contents of the GxPresenceReportingAreaInformation structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxPresenceReportingAreaInformation
(
    GxPresenceReportingAreaInformation *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_OCTETSTRING( data, presence_reporting_area_identifier, buf, buflen, offset );
    PACK_BASIC( data, presence_reporting_area_status, buf, buflen, offset );
    PACK_OCTETSTRING( data, presence_reporting_area_elements_list, buf, buflen, offset );
    PACK_BASIC( data, presence_reporting_area_node, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxConditionalApnAggregateMaxBitrate
*
*       Desc:   Pack the contents of the GxConditionalApnAggregateMaxBitrate structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxConditionalApnAggregateMaxBitrate
(
    GxConditionalApnAggregateMaxBitrate *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, apn_aggregate_max_bitrate_ul, buf, buflen, offset );
    PACK_BASIC( data, apn_aggregate_max_bitrate_dl, buf, buflen, offset );
    PACK_BASIC( data, extended_apn_ambr_ul, buf, buflen, offset );
    PACK_BASIC( data, extended_apn_ambr_dl, buf, buflen, offset );
    PACK_LIST_BASIC( data, ip_can_type, buf, buflen, offset );
    PACK_LIST_BASIC( data, rat_type, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxAccessNetworkChargingIdentifierGx
*
*       Desc:   Pack the contents of the GxAccessNetworkChargingIdentifierGx structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxAccessNetworkChargingIdentifierGx
(
    GxAccessNetworkChargingIdentifierGx *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_OCTETSTRING( data, access_network_charging_identifier_value, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, charging_rule_base_name, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, charging_rule_name, buf, buflen, offset );
    PACK_BASIC( data, ip_can_session_charging_scope, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxOcOlr
*
*       Desc:   Pack the contents of the GxOcOlr structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxOcOlr
(
    GxOcOlr *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, oc_sequence_number, buf, buflen, offset );
    PACK_BASIC( data, oc_report_type, buf, buflen, offset );
    PACK_BASIC( data, oc_reduction_percentage, buf, buflen, offset );
    PACK_BASIC( data, oc_validity_duration, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxRoutingRuleInstall
*
*       Desc:   Pack the contents of the GxRoutingRuleInstall structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Routing-Rule-Install ::= <AVP Header: 1081>
*          *   [ Routing-Rule-Definition ]
*          *   [ AVP ]
*/
static int packGxRoutingRuleInstall
(
    GxRoutingRuleInstall *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_LIST_STRUCT( data, routing_rule_definition, buf, buflen, offset, packGxRoutingRuleDefinition );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxTraceData
*
*       Desc:   Pack the contents of the GxTraceData structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxTraceData
(
    GxTraceData *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_OCTETSTRING( data, trace_reference, buf, buflen, offset );
    PACK_BASIC( data, trace_depth, buf, buflen, offset );
    PACK_OCTETSTRING( data, trace_ne_type_list, buf, buflen, offset );
    PACK_OCTETSTRING( data, trace_interface_list, buf, buflen, offset );
    PACK_OCTETSTRING( data, trace_event_list, buf, buflen, offset );
    PACK_OCTETSTRING( data, omc_id, buf, buflen, offset );
    PACK_BASIC( data, trace_collection_entity, buf, buflen, offset );
    PACK_STRUCT( data, mdt_configuration, buf, buflen, offset, packGxMdtConfiguration );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxRoutingRuleDefinition
*
*       Desc:   Pack the contents of the GxRoutingRuleDefinition structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxRoutingRuleDefinition
(
    GxRoutingRuleDefinition *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_OCTETSTRING( data, routing_rule_identifier, buf, buflen, offset );
    PACK_LIST_STRUCT( data, routing_filter, buf, buflen, offset, packGxRoutingFilter );
    PACK_BASIC( data, precedence, buf, buflen, offset );
    PACK_BASIC( data, routing_ip_address, buf, buflen, offset );
    PACK_BASIC( data, ip_can_type, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxMdtConfiguration
*
*       Desc:   Pack the contents of the GxMdtConfiguration structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxMdtConfiguration
(
    GxMdtConfiguration *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, job_type, buf, buflen, offset );
    PACK_STRUCT( data, area_scope, buf, buflen, offset, packGxAreaScope );
    PACK_BASIC( data, list_of_measurements, buf, buflen, offset );
    PACK_BASIC( data, reporting_trigger, buf, buflen, offset );
    PACK_BASIC( data, report_interval, buf, buflen, offset );
    PACK_BASIC( data, report_amount, buf, buflen, offset );
    PACK_BASIC( data, event_threshold_rsrp, buf, buflen, offset );
    PACK_BASIC( data, event_threshold_rsrq, buf, buflen, offset );
    PACK_BASIC( data, logging_interval, buf, buflen, offset );
    PACK_BASIC( data, logging_duration, buf, buflen, offset );
    PACK_BASIC( data, measurement_period_lte, buf, buflen, offset );
    PACK_BASIC( data, measurement_period_umts, buf, buflen, offset );
    PACK_BASIC( data, collection_period_rrm_lte, buf, buflen, offset );
    PACK_BASIC( data, collection_period_rrm_umts, buf, buflen, offset );
    PACK_OCTETSTRING( data, positioning_method, buf, buflen, offset );
    PACK_OCTETSTRING( data, measurement_quantity, buf, buflen, offset );
    PACK_BASIC( data, event_threshold_event_1f, buf, buflen, offset );
    PACK_BASIC( data, event_threshold_event_1i, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, mdt_allowed_plmn_id, buf, buflen, offset );
    PACK_LIST_STRUCT( data, mbsfn_area, buf, buflen, offset, packGxMbsfnArea );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxChargingRuleRemove
*
*       Desc:   Pack the contents of the GxChargingRuleRemove structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxChargingRuleRemove
(
    GxChargingRuleRemove *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, charging_rule_name, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, charging_rule_base_name, buf, buflen, offset );
    PACK_LIST_BASIC( data, required_access_info, buf, buflen, offset );
    PACK_BASIC( data, resource_release_notification, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxAllocationRetentionPriority
*
*       Desc:   Pack the contents of the GxAllocationRetentionPriority structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Allocation-Retention-Priority ::= <AVP Header: 1034>
*              { Priority-Level }
*              [ Pre-emption-Capability ]
*              [ Pre-emption-Vulnerability ]
*/
static int packGxAllocationRetentionPriority
(
    GxAllocationRetentionPriority *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, priority_level, buf, buflen, offset );
    PACK_BASIC( data, pre_emption_capability, buf, buflen, offset );
    PACK_BASIC( data, pre_emption_vulnerability, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxDefaultEpsBearerQos
*
*       Desc:   Pack the contents of the GxDefaultEpsBearerQos structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Default-EPS-Bearer-QoS ::= <AVP Header: 1049>
*              [ QoS-Class-Identifier ]
*              [ Allocation-Retention-Priority ]
*          *   [ AVP ]
*/
static int packGxDefaultEpsBearerQos
(
    GxDefaultEpsBearerQos *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, qos_class_identifier, buf, buflen, offset );
    PACK_STRUCT( data, allocation_retention_priority, buf, buflen, offset, packGxAllocationRetentionPriority );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxRoutingRuleReport
*
*       Desc:   Pack the contents of the GxRoutingRuleReport structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Routing-Rule-Report ::= <AVP Header: 2835>
*          *   [ Routing-Rule-Identifier ]
*              [ PCC-Rule-Status ]
*              [ Routing-Rule-Failure-Code ]
*          *   [ AVP ]
*/
static int packGxRoutingRuleReport
(
    GxRoutingRuleReport *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, routing_rule_identifier, buf, buflen, offset );
    PACK_BASIC( data, pcc_rule_status, buf, buflen, offset );
    PACK_BASIC( data, routing_rule_failure_code, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxUserEquipmentInfo
*
*       Desc:   Pack the contents of the GxUserEquipmentInfo structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        User-Equipment-Info ::= <AVP Header: 458>
*              { User-Equipment-Info-Type }
*              { User-Equipment-Info-Value }
*/
static int packGxUserEquipmentInfo
(
    GxUserEquipmentInfo *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, user_equipment_info_type, buf, buflen, offset );
    PACK_OCTETSTRING( data, user_equipment_info_value, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxSupportedFeatures
*
*       Desc:   Pack the contents of the GxSupportedFeatures structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Supported-Features ::= <AVP Header: 628>
*              { Vendor-Id }
*              { Feature-List-ID }
*              { Feature-List }
*          *   [ AVP ]
*/
static int packGxSupportedFeatures
(
    GxSupportedFeatures *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, vendor_id, buf, buflen, offset );
    PACK_BASIC( data, feature_list_id, buf, buflen, offset );
    PACK_BASIC( data, feature_list, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxFixedUserLocationInfo
*
*       Desc:   Pack the contents of the GxFixedUserLocationInfo structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxFixedUserLocationInfo
(
    GxFixedUserLocationInfo *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_OCTETSTRING( data, ssid, buf, buflen, offset );
    PACK_OCTETSTRING( data, bssid, buf, buflen, offset );
    PACK_OCTETSTRING( data, logical_access_id, buf, buflen, offset );
    PACK_OCTETSTRING( data, physical_access_id, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxDefaultQosInformation
*
*       Desc:   Pack the contents of the GxDefaultQosInformation structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxDefaultQosInformation
(
    GxDefaultQosInformation *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, qos_class_identifier, buf, buflen, offset );
    PACK_BASIC( data, max_requested_bandwidth_ul, buf, buflen, offset );
    PACK_BASIC( data, max_requested_bandwidth_dl, buf, buflen, offset );
    PACK_OCTETSTRING( data, default_qos_name, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxLoad
*
*       Desc:   Pack the contents of the GxLoad structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Load ::= <AVP Header: 650>
*              [ Load-Type ]
*              [ Load-Value ]
*              [ SourceID ]
*          *   [ AVP ]
*/
static int packGxLoad
(
    GxLoad *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, load_type, buf, buflen, offset );
    PACK_BASIC( data, load_value, buf, buflen, offset );
    PACK_OCTETSTRING( data, sourceid, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxRedirectServer
*
*       Desc:   Pack the contents of the GxRedirectServer structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Redirect-Server ::= <AVP Header: 434>
*              { Redirect-Address-Type }
*              { Redirect-Server-Address }
*/
static int packGxRedirectServer
(
    GxRedirectServer *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, redirect_address_type, buf, buflen, offset );
    PACK_OCTETSTRING( data, redirect_server_address, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxOcSupportedFeatures
*
*       Desc:   Pack the contents of the GxOcSupportedFeatures structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        OC-Supported-Features ::= <AVP Header: 621>
*              [ OC-Feature-Vector ]
*          *   [ AVP ]
*/
static int packGxOcSupportedFeatures
(
    GxOcSupportedFeatures *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, oc_feature_vector, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxPacketFilterInformation
*
*       Desc:   Pack the contents of the GxPacketFilterInformation structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxPacketFilterInformation
(
    GxPacketFilterInformation *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_OCTETSTRING( data, packet_filter_identifier, buf, buflen, offset );
    PACK_BASIC( data, precedence, buf, buflen, offset );
    PACK_OCTETSTRING( data, packet_filter_content, buf, buflen, offset );
    PACK_OCTETSTRING( data, tos_traffic_class, buf, buflen, offset );
    PACK_OCTETSTRING( data, security_parameter_index, buf, buflen, offset );
    PACK_OCTETSTRING( data, flow_label, buf, buflen, offset );
    PACK_BASIC( data, flow_direction, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxSubscriptionId
*
*       Desc:   Pack the contents of the GxSubscriptionId structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Subscription-Id ::= <AVP Header: 443>
*              [ Subscription-Id-Type ]
*              [ Subscription-Id-Data ]
*/
static int packGxSubscriptionId
(
    GxSubscriptionId *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, subscription_id_type, buf, buflen, offset );
    PACK_OCTETSTRING( data, subscription_id_data, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxChargingInformation
*
*       Desc:   Pack the contents of the GxChargingInformation structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxChargingInformation
(
    GxChargingInformation *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_OCTETSTRING( data, primary_event_charging_function_name, buf, buflen, offset );
    PACK_OCTETSTRING( data, secondary_event_charging_function_name, buf, buflen, offset );
    PACK_OCTETSTRING( data, primary_charging_collection_function_name, buf, buflen, offset );
    PACK_OCTETSTRING( data, secondary_charging_collection_function_name, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxUsageMonitoringInformation
*
*       Desc:   Pack the contents of the GxUsageMonitoringInformation structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxUsageMonitoringInformation
(
    GxUsageMonitoringInformation *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_OCTETSTRING( data, monitoring_key, buf, buflen, offset );
    PACK_LIST_STRUCT( data, granted_service_unit, buf, buflen, offset, packGxGrantedServiceUnit );
    PACK_LIST_STRUCT( data, used_service_unit, buf, buflen, offset, packGxUsedServiceUnit );
    PACK_BASIC( data, quota_consumption_time, buf, buflen, offset );
    PACK_BASIC( data, usage_monitoring_level, buf, buflen, offset );
    PACK_BASIC( data, usage_monitoring_report, buf, buflen, offset );
    PACK_BASIC( data, usage_monitoring_support, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxChargingRuleReport
*
*       Desc:   Pack the contents of the GxChargingRuleReport structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxChargingRuleReport
(
    GxChargingRuleReport *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, charging_rule_name, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, charging_rule_base_name, buf, buflen, offset );
    PACK_OCTETSTRING( data, bearer_identifier, buf, buflen, offset );
    PACK_BASIC( data, pcc_rule_status, buf, buflen, offset );
    PACK_BASIC( data, rule_failure_code, buf, buflen, offset );
    PACK_STRUCT( data, final_unit_indication, buf, buflen, offset, packGxFinalUnitIndication );
    PACK_LIST_OCTETSTRING( data, ran_nas_release_cause, buf, buflen, offset );
    PACK_LIST_BASIC( data, content_version, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxRedirectInformation
*
*       Desc:   Pack the contents of the GxRedirectInformation structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Redirect-Information ::= <AVP Header: 1085>
*              [ Redirect-Support ]
*              [ Redirect-Address-Type ]
*              [ Redirect-Server-Address ]
*          *   [ AVP ]
*/
static int packGxRedirectInformation
(
    GxRedirectInformation *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, redirect_support, buf, buflen, offset );
    PACK_BASIC( data, redirect_address_type, buf, buflen, offset );
    PACK_OCTETSTRING( data, redirect_server_address, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxFailedAvp
*
*       Desc:   Pack the contents of the GxFailedAvp structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Failed-AVP ::= <AVP Header: 279>
*         1*   { AVP }
*/
static int packGxFailedAvp
(
    GxFailedAvp *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxRoutingRuleRemove
*
*       Desc:   Pack the contents of the GxRoutingRuleRemove structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Routing-Rule-Remove ::= <AVP Header: 1075>
*          *   [ Routing-Rule-Identifier ]
*          *   [ AVP ]
*/
static int packGxRoutingRuleRemove
(
    GxRoutingRuleRemove *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_LIST_OCTETSTRING( data, routing_rule_identifier, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxRoutingFilter
*
*       Desc:   Pack the contents of the GxRoutingFilter structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxRoutingFilter
(
    GxRoutingFilter *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_OCTETSTRING( data, flow_description, buf, buflen, offset );
    PACK_BASIC( data, flow_direction, buf, buflen, offset );
    PACK_OCTETSTRING( data, tos_traffic_class, buf, buflen, offset );
    PACK_OCTETSTRING( data, security_parameter_index, buf, buflen, offset );
    PACK_OCTETSTRING( data, flow_label, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxCoaInformation
*
*       Desc:   Pack the contents of the GxCoaInformation structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        CoA-Information ::= <AVP Header: 1039>
*              { Tunnel-Information }
*              { CoA-IP-Address }
*          *   [ AVP ]
*/
static int packGxCoaInformation
(
    GxCoaInformation *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_STRUCT( data, tunnel_information, buf, buflen, offset, packGxTunnelInformation );
    PACK_BASIC( data, coa_ip_address, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxGrantedServiceUnit
*
*       Desc:   Pack the contents of the GxGrantedServiceUnit structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxGrantedServiceUnit
(
    GxGrantedServiceUnit *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, tariff_time_change, buf, buflen, offset );
    PACK_BASIC( data, cc_time, buf, buflen, offset );
    PACK_STRUCT( data, cc_money, buf, buflen, offset, packGxCcMoney );
    PACK_BASIC( data, cc_total_octets, buf, buflen, offset );
    PACK_BASIC( data, cc_input_octets, buf, buflen, offset );
    PACK_BASIC( data, cc_output_octets, buf, buflen, offset );
    PACK_BASIC( data, cc_service_specific_units, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxCcMoney
*
*       Desc:   Pack the contents of the GxCcMoney structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        CC-Money ::= <AVP Header: 413>
*              { Unit-Value }
*              [ Currency-Code ]
*/
static int packGxCcMoney
(
    GxCcMoney *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_STRUCT( data, unit_value, buf, buflen, offset, packGxUnitValue );
    PACK_BASIC( data, currency_code, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxApplicationDetectionInformation
*
*       Desc:   Pack the contents of the GxApplicationDetectionInformation structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Application-Detection-Information ::= <AVP Header: 1098>
*              { TDF-Application-Identifier }
*              [ TDF-Application-Instance-Identifier ]
*          *   [ Flow-Information ]
*          *   [ AVP ]
*/
static int packGxApplicationDetectionInformation
(
    GxApplicationDetectionInformation *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_OCTETSTRING( data, tdf_application_identifier, buf, buflen, offset );
    PACK_OCTETSTRING( data, tdf_application_instance_identifier, buf, buflen, offset );
    PACK_LIST_STRUCT( data, flow_information, buf, buflen, offset, packGxFlowInformation );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxFlows
*
*       Desc:   Pack the contents of the GxFlows structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int packGxFlows
(
    GxFlows *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, media_component_number, buf, buflen, offset );
    PACK_LIST_BASIC( data, flow_number, buf, buflen, offset );
    PACK_LIST_BASIC( data, content_version, buf, buflen, offset );
    PACK_BASIC( data, final_unit_action, buf, buflen, offset );
    PACK_BASIC( data, media_component_status, buf, buflen, offset );

    return *offset <= buflen;
}

/*
*
*       Fun:    packGxUserCsgInformation
*
*       Desc:   Pack the contents of the GxUserCsgInformation structure
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        User-CSG-Information ::= <AVP Header: 2319>
*              { CSG-Id }
*              { CSG-Access-Mode }
*              [ CSG-Membership-Indication ]
*/
static int packGxUserCsgInformation
(
    GxUserCsgInformation *data,
    unsigned char *buf,
    uint32_t buflen,
    uint32_t *offset
)
{
    PACK_PRESENCE( data, presence, buf, buflen, offset );
    PACK_BASIC( data, csg_id, buf, buflen, offset );
    PACK_BASIC( data, csg_access_mode, buf, buflen, offset );
    PACK_BASIC( data, csg_membership_indication, buf, buflen, offset );

    return *offset <= buflen;
}

/*******************************************************************************/
/* structure unpack functions                                                  */
/*******************************************************************************/

/*
*
*       Fun:    unpackGxExperimentalResult
*
*       Desc:   Unpack the specified buffer into GxExperimentalResult
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Experimental-Result ::= <AVP Header: 297>
*              { Vendor-Id }
*              { Experimental-Result-Code }
*/
static int unpackGxExperimentalResult
(
    unsigned char *buf,
    uint32_t length,
    GxExperimentalResult *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, vendor_id, buf, length, offset );
    UNPACK_BASIC( data, experimental_result_code, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxPraRemove
*
*       Desc:   Unpack the specified buffer into GxPraRemove
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        PRA-Remove ::= <AVP Header: 2846>
*          *   [ Presence-Reporting-Area-Identifier ]
*          *   [ AVP ]
*/
static int unpackGxPraRemove
(
    unsigned char *buf,
    uint32_t length,
    GxPraRemove *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, presence_reporting_area_identifier, GxPresenceReportingAreaIdentifierOctetString, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxQosInformation
*
*       Desc:   Unpack the specified buffer into GxQosInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxQosInformation
(
    unsigned char *buf,
    uint32_t length,
    GxQosInformation *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, qos_class_identifier, buf, length, offset );
    UNPACK_BASIC( data, max_requested_bandwidth_ul, buf, length, offset );
    UNPACK_BASIC( data, max_requested_bandwidth_dl, buf, length, offset );
    UNPACK_BASIC( data, extended_max_requested_bw_ul, buf, length, offset );
    UNPACK_BASIC( data, extended_max_requested_bw_dl, buf, length, offset );
    UNPACK_BASIC( data, guaranteed_bitrate_ul, buf, length, offset );
    UNPACK_BASIC( data, guaranteed_bitrate_dl, buf, length, offset );
    UNPACK_BASIC( data, extended_gbr_ul, buf, length, offset );
    UNPACK_BASIC( data, extended_gbr_dl, buf, length, offset );
    UNPACK_OCTETSTRING( data, bearer_identifier, buf, length, offset );
    UNPACK_STRUCT( data, allocation_retention_priority, buf, length, offset, unpackGxAllocationRetentionPriority );
    UNPACK_BASIC( data, apn_aggregate_max_bitrate_ul, buf, length, offset );
    UNPACK_BASIC( data, apn_aggregate_max_bitrate_dl, buf, length, offset );
    UNPACK_BASIC( data, extended_apn_ambr_ul, buf, length, offset );
    UNPACK_BASIC( data, extended_apn_ambr_dl, buf, length, offset );
    UNPACK_LIST_STRUCT( data, conditional_apn_aggregate_max_bitrate, GxConditionalApnAggregateMaxBitrate, buf, length, offset, unpackGxConditionalApnAggregateMaxBitrate );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxConditionalPolicyInformation
*
*       Desc:   Unpack the specified buffer into GxConditionalPolicyInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxConditionalPolicyInformation
(
    unsigned char *buf,
    uint32_t length,
    GxConditionalPolicyInformation *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, execution_time, buf, length, offset );
    UNPACK_STRUCT( data, default_eps_bearer_qos, buf, length, offset, unpackGxDefaultEpsBearerQos );
    UNPACK_BASIC( data, apn_aggregate_max_bitrate_ul, buf, length, offset );
    UNPACK_BASIC( data, apn_aggregate_max_bitrate_dl, buf, length, offset );
    UNPACK_BASIC( data, extended_apn_ambr_ul, buf, length, offset );
    UNPACK_BASIC( data, extended_apn_ambr_dl, buf, length, offset );
    UNPACK_LIST_STRUCT( data, conditional_apn_aggregate_max_bitrate, GxConditionalApnAggregateMaxBitrate, buf, length, offset, unpackGxConditionalApnAggregateMaxBitrate );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxPraInstall
*
*       Desc:   Unpack the specified buffer into GxPraInstall
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        PRA-Install ::= <AVP Header: 2845>
*          *   [ Presence-Reporting-Area-Information ]
*          *   [ AVP ]
*/
static int unpackGxPraInstall
(
    unsigned char *buf,
    uint32_t length,
    GxPraInstall *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_LIST_STRUCT( data, presence_reporting_area_information, GxPresenceReportingAreaInformation, buf, length, offset, unpackGxPresenceReportingAreaInformation );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxAreaScope
*
*       Desc:   Unpack the specified buffer into GxAreaScope
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxAreaScope
(
    unsigned char *buf,
    uint32_t length,
    GxAreaScope *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, cell_global_identity, GxCellGlobalIdentityOctetString, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, e_utran_cell_global_identity, GxEUtranCellGlobalIdentityOctetString, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, routing_area_identity, GxRoutingAreaIdentityOctetString, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, location_area_identity, GxLocationAreaIdentityOctetString, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, tracking_area_identity, GxTrackingAreaIdentityOctetString, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxFlowInformation
*
*       Desc:   Unpack the specified buffer into GxFlowInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxFlowInformation
(
    unsigned char *buf,
    uint32_t length,
    GxFlowInformation *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_OCTETSTRING( data, flow_description, buf, length, offset );
    UNPACK_OCTETSTRING( data, packet_filter_identifier, buf, length, offset );
    UNPACK_BASIC( data, packet_filter_usage, buf, length, offset );
    UNPACK_OCTETSTRING( data, tos_traffic_class, buf, length, offset );
    UNPACK_OCTETSTRING( data, security_parameter_index, buf, length, offset );
    UNPACK_OCTETSTRING( data, flow_label, buf, length, offset );
    UNPACK_BASIC( data, flow_direction, buf, length, offset );
    UNPACK_OCTETSTRING( data, routing_rule_identifier, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxTunnelInformation
*
*       Desc:   Unpack the specified buffer into GxTunnelInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Tunnel-Information ::= <AVP Header: 1038>
*              [ Tunnel-Header-Length ]
*              [ Tunnel-Header-Filter ]
*/
static int unpackGxTunnelInformation
(
    unsigned char *buf,
    uint32_t length,
    GxTunnelInformation *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, tunnel_header_length, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, tunnel_header_filter, GxTunnelHeaderFilterOctetString, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxTftPacketFilterInformation
*
*       Desc:   Unpack the specified buffer into GxTftPacketFilterInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxTftPacketFilterInformation
(
    unsigned char *buf,
    uint32_t length,
    GxTftPacketFilterInformation *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, precedence, buf, length, offset );
    UNPACK_OCTETSTRING( data, tft_filter, buf, length, offset );
    UNPACK_OCTETSTRING( data, tos_traffic_class, buf, length, offset );
    UNPACK_OCTETSTRING( data, security_parameter_index, buf, length, offset );
    UNPACK_OCTETSTRING( data, flow_label, buf, length, offset );
    UNPACK_BASIC( data, flow_direction, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxMbsfnArea
*
*       Desc:   Unpack the specified buffer into GxMbsfnArea
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        MBSFN-Area ::= <AVP Header: 1694>
*              { MBSFN-Area-ID }
*              { Carrier-Frequency }
*          *   [ AVP ]
*/
static int unpackGxMbsfnArea
(
    unsigned char *buf,
    uint32_t length,
    GxMbsfnArea *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, mbsfn_area_id, buf, length, offset );
    UNPACK_BASIC( data, carrier_frequency, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxEventReportIndication
*
*       Desc:   Unpack the specified buffer into GxEventReportIndication
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxEventReportIndication
(
    unsigned char *buf,
    uint32_t length,
    GxEventReportIndication *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, an_trusted, buf, length, offset );
    UNPACK_LIST_BASIC( data, event_trigger, int32_t, buf, length, offset );
    UNPACK_STRUCT( data, user_csg_information, buf, length, offset, unpackGxUserCsgInformation );
    UNPACK_BASIC( data, ip_can_type, buf, length, offset );
    UNPACK_LIST_BASIC( data, an_gw_address, FdAddress, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp_sgsn_address, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp_sgsn_ipv6_address, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp_sgsn_mcc_mnc, buf, length, offset );
    UNPACK_OCTETSTRING( data, framed_ip_address, buf, length, offset );
    UNPACK_BASIC( data, rat_type, buf, length, offset );
    UNPACK_OCTETSTRING( data, rai, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp_user_location_info, buf, length, offset );
    UNPACK_STRUCT( data, trace_data, buf, length, offset, unpackGxTraceData );
    UNPACK_OCTETSTRING( data, trace_reference, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp2_bsid, buf, length, offset );
    UNPACK_OCTETSTRING( data, tgpp_ms_timezone, buf, length, offset );
    UNPACK_BASIC( data, routing_ip_address, buf, length, offset );
    UNPACK_BASIC( data, ue_local_ip_address, buf, length, offset );
    UNPACK_BASIC( data, henb_local_ip_address, buf, length, offset );
    UNPACK_BASIC( data, udp_source_port, buf, length, offset );
    UNPACK_STRUCT( data, presence_reporting_area_information, buf, length, offset, unpackGxPresenceReportingAreaInformation );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxTdfInformation
*
*       Desc:   Unpack the specified buffer into GxTdfInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        TDF-Information ::= <AVP Header: 1087>
*              [ TDF-Destination-Realm ]
*              [ TDF-Destination-Host ]
*              [ TDF-IP-Address ]
*/
static int unpackGxTdfInformation
(
    unsigned char *buf,
    uint32_t length,
    GxTdfInformation *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_OCTETSTRING( data, tdf_destination_realm, buf, length, offset );
    UNPACK_OCTETSTRING( data, tdf_destination_host, buf, length, offset );
    UNPACK_BASIC( data, tdf_ip_address, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxProxyInfo
*
*       Desc:   Unpack the specified buffer into GxProxyInfo
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Proxy-Info ::= <AVP Header: 284>
*              { Proxy-Host }
*              { Proxy-State }
*          *   [ AVP ]
*/
static int unpackGxProxyInfo
(
    unsigned char *buf,
    uint32_t length,
    GxProxyInfo *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_OCTETSTRING( data, proxy_host, buf, length, offset );
    UNPACK_OCTETSTRING( data, proxy_state, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxUsedServiceUnit
*
*       Desc:   Unpack the specified buffer into GxUsedServiceUnit
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxUsedServiceUnit
(
    unsigned char *buf,
    uint32_t length,
    GxUsedServiceUnit *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, reporting_reason, buf, length, offset );
    UNPACK_BASIC( data, tariff_change_usage, buf, length, offset );
    UNPACK_BASIC( data, cc_time, buf, length, offset );
    UNPACK_STRUCT( data, cc_money, buf, length, offset, unpackGxCcMoney );
    UNPACK_BASIC( data, cc_total_octets, buf, length, offset );
    UNPACK_BASIC( data, cc_input_octets, buf, length, offset );
    UNPACK_BASIC( data, cc_output_octets, buf, length, offset );
    UNPACK_BASIC( data, cc_service_specific_units, buf, length, offset );
    UNPACK_LIST_BASIC( data, event_charging_timestamp, FdTime, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxChargingRuleInstall
*
*       Desc:   Unpack the specified buffer into GxChargingRuleInstall
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxChargingRuleInstall
(
    unsigned char *buf,
    uint32_t length,
    GxChargingRuleInstall *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_LIST_STRUCT( data, charging_rule_definition, GxChargingRuleDefinition, buf, length, offset, unpackGxChargingRuleDefinition );
    UNPACK_LIST_OCTETSTRING( data, charging_rule_name, GxChargingRuleNameOctetString, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, charging_rule_base_name, GxChargingRuleBaseNameOctetString, buf, length, offset );
    UNPACK_OCTETSTRING( data, bearer_identifier, buf, length, offset );
    UNPACK_BASIC( data, monitoring_flags, buf, length, offset );
    UNPACK_BASIC( data, rule_activation_time, buf, length, offset );
    UNPACK_BASIC( data, rule_deactivation_time, buf, length, offset );
    UNPACK_BASIC( data, resource_allocation_notification, buf, length, offset );
    UNPACK_BASIC( data, charging_correlation_indicator, buf, length, offset );
    UNPACK_BASIC( data, ip_can_type, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxChargingRuleDefinition
*
*       Desc:   Unpack the specified buffer into GxChargingRuleDefinition
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxChargingRuleDefinition
(
    unsigned char *buf,
    uint32_t length,
    GxChargingRuleDefinition *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_OCTETSTRING( data, charging_rule_name, buf, length, offset );
    UNPACK_BASIC( data, service_identifier, buf, length, offset );
    UNPACK_BASIC( data, rating_group, buf, length, offset );
    UNPACK_LIST_STRUCT( data, flow_information, GxFlowInformation, buf, length, offset, unpackGxFlowInformation );
    UNPACK_BASIC( data, default_bearer_indication, buf, length, offset );
    UNPACK_OCTETSTRING( data, tdf_application_identifier, buf, length, offset );
    UNPACK_BASIC( data, flow_status, buf, length, offset );
    UNPACK_STRUCT( data, qos_information, buf, length, offset, unpackGxQosInformation );
    UNPACK_BASIC( data, ps_to_cs_session_continuity, buf, length, offset );
    UNPACK_BASIC( data, reporting_level, buf, length, offset );
    UNPACK_BASIC( data, online, buf, length, offset );
    UNPACK_BASIC( data, offline, buf, length, offset );
    UNPACK_BASIC( data, max_plr_dl, buf, length, offset );
    UNPACK_BASIC( data, max_plr_ul, buf, length, offset );
    UNPACK_BASIC( data, metering_method, buf, length, offset );
    UNPACK_BASIC( data, precedence, buf, length, offset );
    UNPACK_OCTETSTRING( data, af_charging_identifier, buf, length, offset );
    UNPACK_LIST_STRUCT( data, flows, GxFlows, buf, length, offset, unpackGxFlows );
    UNPACK_OCTETSTRING( data, monitoring_key, buf, length, offset );
    UNPACK_STRUCT( data, redirect_information, buf, length, offset, unpackGxRedirectInformation );
    UNPACK_BASIC( data, mute_notification, buf, length, offset );
    UNPACK_BASIC( data, af_signalling_protocol, buf, length, offset );
    UNPACK_OCTETSTRING( data, sponsor_identity, buf, length, offset );
    UNPACK_OCTETSTRING( data, application_service_provider_identity, buf, length, offset );
    UNPACK_LIST_BASIC( data, required_access_info, int32_t, buf, length, offset );
    UNPACK_BASIC( data, sharing_key_dl, buf, length, offset );
    UNPACK_BASIC( data, sharing_key_ul, buf, length, offset );
    UNPACK_OCTETSTRING( data, traffic_steering_policy_identifier_dl, buf, length, offset );
    UNPACK_OCTETSTRING( data, traffic_steering_policy_identifier_ul, buf, length, offset );
    UNPACK_BASIC( data, content_version, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxFinalUnitIndication
*
*       Desc:   Unpack the specified buffer into GxFinalUnitIndication
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Final-Unit-Indication ::= <AVP Header: 430>
*              { Final-Unit-Action }
*          *   [ Restriction-Filter-Rule ]
*          *   [ Filter-Id ]
*              [ Redirect-Server ]
*/
static int unpackGxFinalUnitIndication
(
    unsigned char *buf,
    uint32_t length,
    GxFinalUnitIndication *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, final_unit_action, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, restriction_filter_rule, GxRestrictionFilterRuleOctetString, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, filter_id, GxFilterIdOctetString, buf, length, offset );
    UNPACK_STRUCT( data, redirect_server, buf, length, offset, unpackGxRedirectServer );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxUnitValue
*
*       Desc:   Unpack the specified buffer into GxUnitValue
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Unit-Value ::= <AVP Header: 445>
*              { Value-Digits }
*              [ Exponent ]
*/
static int unpackGxUnitValue
(
    unsigned char *buf,
    uint32_t length,
    GxUnitValue *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, value_digits, buf, length, offset );
    UNPACK_BASIC( data, exponent, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxPresenceReportingAreaInformation
*
*       Desc:   Unpack the specified buffer into GxPresenceReportingAreaInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxPresenceReportingAreaInformation
(
    unsigned char *buf,
    uint32_t length,
    GxPresenceReportingAreaInformation *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_OCTETSTRING( data, presence_reporting_area_identifier, buf, length, offset );
    UNPACK_BASIC( data, presence_reporting_area_status, buf, length, offset );
    UNPACK_OCTETSTRING( data, presence_reporting_area_elements_list, buf, length, offset );
    UNPACK_BASIC( data, presence_reporting_area_node, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxConditionalApnAggregateMaxBitrate
*
*       Desc:   Unpack the specified buffer into GxConditionalApnAggregateMaxBitrate
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxConditionalApnAggregateMaxBitrate
(
    unsigned char *buf,
    uint32_t length,
    GxConditionalApnAggregateMaxBitrate *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, apn_aggregate_max_bitrate_ul, buf, length, offset );
    UNPACK_BASIC( data, apn_aggregate_max_bitrate_dl, buf, length, offset );
    UNPACK_BASIC( data, extended_apn_ambr_ul, buf, length, offset );
    UNPACK_BASIC( data, extended_apn_ambr_dl, buf, length, offset );
    UNPACK_LIST_BASIC( data, ip_can_type, int32_t, buf, length, offset );
    UNPACK_LIST_BASIC( data, rat_type, int32_t, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxAccessNetworkChargingIdentifierGx
*
*       Desc:   Unpack the specified buffer into GxAccessNetworkChargingIdentifierGx
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxAccessNetworkChargingIdentifierGx
(
    unsigned char *buf,
    uint32_t length,
    GxAccessNetworkChargingIdentifierGx *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_OCTETSTRING( data, access_network_charging_identifier_value, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, charging_rule_base_name, GxChargingRuleBaseNameOctetString, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, charging_rule_name, GxChargingRuleNameOctetString, buf, length, offset );
    UNPACK_BASIC( data, ip_can_session_charging_scope, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxOcOlr
*
*       Desc:   Unpack the specified buffer into GxOcOlr
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxOcOlr
(
    unsigned char *buf,
    uint32_t length,
    GxOcOlr *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, oc_sequence_number, buf, length, offset );
    UNPACK_BASIC( data, oc_report_type, buf, length, offset );
    UNPACK_BASIC( data, oc_reduction_percentage, buf, length, offset );
    UNPACK_BASIC( data, oc_validity_duration, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxRoutingRuleInstall
*
*       Desc:   Unpack the specified buffer into GxRoutingRuleInstall
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Routing-Rule-Install ::= <AVP Header: 1081>
*          *   [ Routing-Rule-Definition ]
*          *   [ AVP ]
*/
static int unpackGxRoutingRuleInstall
(
    unsigned char *buf,
    uint32_t length,
    GxRoutingRuleInstall *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_LIST_STRUCT( data, routing_rule_definition, GxRoutingRuleDefinition, buf, length, offset, unpackGxRoutingRuleDefinition );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxTraceData
*
*       Desc:   Unpack the specified buffer into GxTraceData
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxTraceData
(
    unsigned char *buf,
    uint32_t length,
    GxTraceData *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_OCTETSTRING( data, trace_reference, buf, length, offset );
    UNPACK_BASIC( data, trace_depth, buf, length, offset );
    UNPACK_OCTETSTRING( data, trace_ne_type_list, buf, length, offset );
    UNPACK_OCTETSTRING( data, trace_interface_list, buf, length, offset );
    UNPACK_OCTETSTRING( data, trace_event_list, buf, length, offset );
    UNPACK_OCTETSTRING( data, omc_id, buf, length, offset );
    UNPACK_BASIC( data, trace_collection_entity, buf, length, offset );
    UNPACK_STRUCT( data, mdt_configuration, buf, length, offset, unpackGxMdtConfiguration );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxRoutingRuleDefinition
*
*       Desc:   Unpack the specified buffer into GxRoutingRuleDefinition
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxRoutingRuleDefinition
(
    unsigned char *buf,
    uint32_t length,
    GxRoutingRuleDefinition *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_OCTETSTRING( data, routing_rule_identifier, buf, length, offset );
    UNPACK_LIST_STRUCT( data, routing_filter, GxRoutingFilter, buf, length, offset, unpackGxRoutingFilter );
    UNPACK_BASIC( data, precedence, buf, length, offset );
    UNPACK_BASIC( data, routing_ip_address, buf, length, offset );
    UNPACK_BASIC( data, ip_can_type, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxMdtConfiguration
*
*       Desc:   Unpack the specified buffer into GxMdtConfiguration
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxMdtConfiguration
(
    unsigned char *buf,
    uint32_t length,
    GxMdtConfiguration *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, job_type, buf, length, offset );
    UNPACK_STRUCT( data, area_scope, buf, length, offset, unpackGxAreaScope );
    UNPACK_BASIC( data, list_of_measurements, buf, length, offset );
    UNPACK_BASIC( data, reporting_trigger, buf, length, offset );
    UNPACK_BASIC( data, report_interval, buf, length, offset );
    UNPACK_BASIC( data, report_amount, buf, length, offset );
    UNPACK_BASIC( data, event_threshold_rsrp, buf, length, offset );
    UNPACK_BASIC( data, event_threshold_rsrq, buf, length, offset );
    UNPACK_BASIC( data, logging_interval, buf, length, offset );
    UNPACK_BASIC( data, logging_duration, buf, length, offset );
    UNPACK_BASIC( data, measurement_period_lte, buf, length, offset );
    UNPACK_BASIC( data, measurement_period_umts, buf, length, offset );
    UNPACK_BASIC( data, collection_period_rrm_lte, buf, length, offset );
    UNPACK_BASIC( data, collection_period_rrm_umts, buf, length, offset );
    UNPACK_OCTETSTRING( data, positioning_method, buf, length, offset );
    UNPACK_OCTETSTRING( data, measurement_quantity, buf, length, offset );
    UNPACK_BASIC( data, event_threshold_event_1f, buf, length, offset );
    UNPACK_BASIC( data, event_threshold_event_1i, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, mdt_allowed_plmn_id, GxMdtAllowedPlmnIdOctetString, buf, length, offset );
    UNPACK_LIST_STRUCT( data, mbsfn_area, GxMbsfnArea, buf, length, offset, unpackGxMbsfnArea );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxChargingRuleRemove
*
*       Desc:   Unpack the specified buffer into GxChargingRuleRemove
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxChargingRuleRemove
(
    unsigned char *buf,
    uint32_t length,
    GxChargingRuleRemove *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, charging_rule_name, GxChargingRuleNameOctetString, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, charging_rule_base_name, GxChargingRuleBaseNameOctetString, buf, length, offset );
    UNPACK_LIST_BASIC( data, required_access_info, int32_t, buf, length, offset );
    UNPACK_BASIC( data, resource_release_notification, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxAllocationRetentionPriority
*
*       Desc:   Unpack the specified buffer into GxAllocationRetentionPriority
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Allocation-Retention-Priority ::= <AVP Header: 1034>
*              { Priority-Level }
*              [ Pre-emption-Capability ]
*              [ Pre-emption-Vulnerability ]
*/
static int unpackGxAllocationRetentionPriority
(
    unsigned char *buf,
    uint32_t length,
    GxAllocationRetentionPriority *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, priority_level, buf, length, offset );
    UNPACK_BASIC( data, pre_emption_capability, buf, length, offset );
    UNPACK_BASIC( data, pre_emption_vulnerability, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxDefaultEpsBearerQos
*
*       Desc:   Unpack the specified buffer into GxDefaultEpsBearerQos
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Default-EPS-Bearer-QoS ::= <AVP Header: 1049>
*              [ QoS-Class-Identifier ]
*              [ Allocation-Retention-Priority ]
*          *   [ AVP ]
*/
static int unpackGxDefaultEpsBearerQos
(
    unsigned char *buf,
    uint32_t length,
    GxDefaultEpsBearerQos *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, qos_class_identifier, buf, length, offset );
    UNPACK_STRUCT( data, allocation_retention_priority, buf, length, offset, unpackGxAllocationRetentionPriority );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxRoutingRuleReport
*
*       Desc:   Unpack the specified buffer into GxRoutingRuleReport
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Routing-Rule-Report ::= <AVP Header: 2835>
*          *   [ Routing-Rule-Identifier ]
*              [ PCC-Rule-Status ]
*              [ Routing-Rule-Failure-Code ]
*          *   [ AVP ]
*/
static int unpackGxRoutingRuleReport
(
    unsigned char *buf,
    uint32_t length,
    GxRoutingRuleReport *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, routing_rule_identifier, GxRoutingRuleIdentifierOctetString, buf, length, offset );
    UNPACK_BASIC( data, pcc_rule_status, buf, length, offset );
    UNPACK_BASIC( data, routing_rule_failure_code, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxUserEquipmentInfo
*
*       Desc:   Unpack the specified buffer into GxUserEquipmentInfo
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        User-Equipment-Info ::= <AVP Header: 458>
*              { User-Equipment-Info-Type }
*              { User-Equipment-Info-Value }
*/
static int unpackGxUserEquipmentInfo
(
    unsigned char *buf,
    uint32_t length,
    GxUserEquipmentInfo *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, user_equipment_info_type, buf, length, offset );
    UNPACK_OCTETSTRING( data, user_equipment_info_value, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxSupportedFeatures
*
*       Desc:   Unpack the specified buffer into GxSupportedFeatures
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Supported-Features ::= <AVP Header: 628>
*              { Vendor-Id }
*              { Feature-List-ID }
*              { Feature-List }
*          *   [ AVP ]
*/
static int unpackGxSupportedFeatures
(
    unsigned char *buf,
    uint32_t length,
    GxSupportedFeatures *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, vendor_id, buf, length, offset );
    UNPACK_BASIC( data, feature_list_id, buf, length, offset );
    UNPACK_BASIC( data, feature_list, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxFixedUserLocationInfo
*
*       Desc:   Unpack the specified buffer into GxFixedUserLocationInfo
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxFixedUserLocationInfo
(
    unsigned char *buf,
    uint32_t length,
    GxFixedUserLocationInfo *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_OCTETSTRING( data, ssid, buf, length, offset );
    UNPACK_OCTETSTRING( data, bssid, buf, length, offset );
    UNPACK_OCTETSTRING( data, logical_access_id, buf, length, offset );
    UNPACK_OCTETSTRING( data, physical_access_id, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxDefaultQosInformation
*
*       Desc:   Unpack the specified buffer into GxDefaultQosInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxDefaultQosInformation
(
    unsigned char *buf,
    uint32_t length,
    GxDefaultQosInformation *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, qos_class_identifier, buf, length, offset );
    UNPACK_BASIC( data, max_requested_bandwidth_ul, buf, length, offset );
    UNPACK_BASIC( data, max_requested_bandwidth_dl, buf, length, offset );
    UNPACK_OCTETSTRING( data, default_qos_name, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxLoad
*
*       Desc:   Unpack the specified buffer into GxLoad
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Load ::= <AVP Header: 650>
*              [ Load-Type ]
*              [ Load-Value ]
*              [ SourceID ]
*          *   [ AVP ]
*/
static int unpackGxLoad
(
    unsigned char *buf,
    uint32_t length,
    GxLoad *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, load_type, buf, length, offset );
    UNPACK_BASIC( data, load_value, buf, length, offset );
    UNPACK_OCTETSTRING( data, sourceid, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxRedirectServer
*
*       Desc:   Unpack the specified buffer into GxRedirectServer
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Redirect-Server ::= <AVP Header: 434>
*              { Redirect-Address-Type }
*              { Redirect-Server-Address }
*/
static int unpackGxRedirectServer
(
    unsigned char *buf,
    uint32_t length,
    GxRedirectServer *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, redirect_address_type, buf, length, offset );
    UNPACK_OCTETSTRING( data, redirect_server_address, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxOcSupportedFeatures
*
*       Desc:   Unpack the specified buffer into GxOcSupportedFeatures
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        OC-Supported-Features ::= <AVP Header: 621>
*              [ OC-Feature-Vector ]
*          *   [ AVP ]
*/
static int unpackGxOcSupportedFeatures
(
    unsigned char *buf,
    uint32_t length,
    GxOcSupportedFeatures *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, oc_feature_vector, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxPacketFilterInformation
*
*       Desc:   Unpack the specified buffer into GxPacketFilterInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxPacketFilterInformation
(
    unsigned char *buf,
    uint32_t length,
    GxPacketFilterInformation *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_OCTETSTRING( data, packet_filter_identifier, buf, length, offset );
    UNPACK_BASIC( data, precedence, buf, length, offset );
    UNPACK_OCTETSTRING( data, packet_filter_content, buf, length, offset );
    UNPACK_OCTETSTRING( data, tos_traffic_class, buf, length, offset );
    UNPACK_OCTETSTRING( data, security_parameter_index, buf, length, offset );
    UNPACK_OCTETSTRING( data, flow_label, buf, length, offset );
    UNPACK_BASIC( data, flow_direction, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxSubscriptionId
*
*       Desc:   Unpack the specified buffer into GxSubscriptionId
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Subscription-Id ::= <AVP Header: 443>
*              [ Subscription-Id-Type ]
*              [ Subscription-Id-Data ]
*/
static int unpackGxSubscriptionId
(
    unsigned char *buf,
    uint32_t length,
    GxSubscriptionId *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, subscription_id_type, buf, length, offset );
    UNPACK_OCTETSTRING( data, subscription_id_data, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxChargingInformation
*
*       Desc:   Unpack the specified buffer into GxChargingInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxChargingInformation
(
    unsigned char *buf,
    uint32_t length,
    GxChargingInformation *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_OCTETSTRING( data, primary_event_charging_function_name, buf, length, offset );
    UNPACK_OCTETSTRING( data, secondary_event_charging_function_name, buf, length, offset );
    UNPACK_OCTETSTRING( data, primary_charging_collection_function_name, buf, length, offset );
    UNPACK_OCTETSTRING( data, secondary_charging_collection_function_name, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxUsageMonitoringInformation
*
*       Desc:   Unpack the specified buffer into GxUsageMonitoringInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxUsageMonitoringInformation
(
    unsigned char *buf,
    uint32_t length,
    GxUsageMonitoringInformation *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_OCTETSTRING( data, monitoring_key, buf, length, offset );
    UNPACK_LIST_STRUCT( data, granted_service_unit, GxGrantedServiceUnit, buf, length, offset, unpackGxGrantedServiceUnit );
    UNPACK_LIST_STRUCT( data, used_service_unit, GxUsedServiceUnit, buf, length, offset, unpackGxUsedServiceUnit );
    UNPACK_BASIC( data, quota_consumption_time, buf, length, offset );
    UNPACK_BASIC( data, usage_monitoring_level, buf, length, offset );
    UNPACK_BASIC( data, usage_monitoring_report, buf, length, offset );
    UNPACK_BASIC( data, usage_monitoring_support, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxChargingRuleReport
*
*       Desc:   Unpack the specified buffer into GxChargingRuleReport
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxChargingRuleReport
(
    unsigned char *buf,
    uint32_t length,
    GxChargingRuleReport *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, charging_rule_name, GxChargingRuleNameOctetString, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, charging_rule_base_name, GxChargingRuleBaseNameOctetString, buf, length, offset );
    UNPACK_OCTETSTRING( data, bearer_identifier, buf, length, offset );
    UNPACK_BASIC( data, pcc_rule_status, buf, length, offset );
    UNPACK_BASIC( data, rule_failure_code, buf, length, offset );
    UNPACK_STRUCT( data, final_unit_indication, buf, length, offset, unpackGxFinalUnitIndication );
    UNPACK_LIST_OCTETSTRING( data, ran_nas_release_cause, GxRanNasReleaseCauseOctetString, buf, length, offset );
    UNPACK_LIST_BASIC( data, content_version, uint64_t, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxRedirectInformation
*
*       Desc:   Unpack the specified buffer into GxRedirectInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Redirect-Information ::= <AVP Header: 1085>
*              [ Redirect-Support ]
*              [ Redirect-Address-Type ]
*              [ Redirect-Server-Address ]
*          *   [ AVP ]
*/
static int unpackGxRedirectInformation
(
    unsigned char *buf,
    uint32_t length,
    GxRedirectInformation *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, redirect_support, buf, length, offset );
    UNPACK_BASIC( data, redirect_address_type, buf, length, offset );
    UNPACK_OCTETSTRING( data, redirect_server_address, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxFailedAvp
*
*       Desc:   Unpack the specified buffer into GxFailedAvp
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Failed-AVP ::= <AVP Header: 279>
*         1*   { AVP }
*/
static int unpackGxFailedAvp
(
    unsigned char *buf,
    uint32_t length,
    GxFailedAvp *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxRoutingRuleRemove
*
*       Desc:   Unpack the specified buffer into GxRoutingRuleRemove
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Routing-Rule-Remove ::= <AVP Header: 1075>
*          *   [ Routing-Rule-Identifier ]
*          *   [ AVP ]
*/
static int unpackGxRoutingRuleRemove
(
    unsigned char *buf,
    uint32_t length,
    GxRoutingRuleRemove *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_LIST_OCTETSTRING( data, routing_rule_identifier, GxRoutingRuleIdentifierOctetString, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxRoutingFilter
*
*       Desc:   Unpack the specified buffer into GxRoutingFilter
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxRoutingFilter
(
    unsigned char *buf,
    uint32_t length,
    GxRoutingFilter *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_OCTETSTRING( data, flow_description, buf, length, offset );
    UNPACK_BASIC( data, flow_direction, buf, length, offset );
    UNPACK_OCTETSTRING( data, tos_traffic_class, buf, length, offset );
    UNPACK_OCTETSTRING( data, security_parameter_index, buf, length, offset );
    UNPACK_OCTETSTRING( data, flow_label, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxCoaInformation
*
*       Desc:   Unpack the specified buffer into GxCoaInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        CoA-Information ::= <AVP Header: 1039>
*              { Tunnel-Information }
*              { CoA-IP-Address }
*          *   [ AVP ]
*/
static int unpackGxCoaInformation
(
    unsigned char *buf,
    uint32_t length,
    GxCoaInformation *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_STRUCT( data, tunnel_information, buf, length, offset, unpackGxTunnelInformation );
    UNPACK_BASIC( data, coa_ip_address, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxGrantedServiceUnit
*
*       Desc:   Unpack the specified buffer into GxGrantedServiceUnit
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxGrantedServiceUnit
(
    unsigned char *buf,
    uint32_t length,
    GxGrantedServiceUnit *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, tariff_time_change, buf, length, offset );
    UNPACK_BASIC( data, cc_time, buf, length, offset );
    UNPACK_STRUCT( data, cc_money, buf, length, offset, unpackGxCcMoney );
    UNPACK_BASIC( data, cc_total_octets, buf, length, offset );
    UNPACK_BASIC( data, cc_input_octets, buf, length, offset );
    UNPACK_BASIC( data, cc_output_octets, buf, length, offset );
    UNPACK_BASIC( data, cc_service_specific_units, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxCcMoney
*
*       Desc:   Unpack the specified buffer into GxCcMoney
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        CC-Money ::= <AVP Header: 413>
*              { Unit-Value }
*              [ Currency-Code ]
*/
static int unpackGxCcMoney
(
    unsigned char *buf,
    uint32_t length,
    GxCcMoney *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_STRUCT( data, unit_value, buf, length, offset, unpackGxUnitValue );
    UNPACK_BASIC( data, currency_code, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxApplicationDetectionInformation
*
*       Desc:   Unpack the specified buffer into GxApplicationDetectionInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        Application-Detection-Information ::= <AVP Header: 1098>
*              { TDF-Application-Identifier }
*              [ TDF-Application-Instance-Identifier ]
*          *   [ Flow-Information ]
*          *   [ AVP ]
*/
static int unpackGxApplicationDetectionInformation
(
    unsigned char *buf,
    uint32_t length,
    GxApplicationDetectionInformation *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_OCTETSTRING( data, tdf_application_identifier, buf, length, offset );
    UNPACK_OCTETSTRING( data, tdf_application_instance_identifier, buf, length, offset );
    UNPACK_LIST_STRUCT( data, flow_information, GxFlowInformation, buf, length, offset, unpackGxFlowInformation );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxFlows
*
*       Desc:   Unpack the specified buffer into GxFlows
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
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
static int unpackGxFlows
(
    unsigned char *buf,
    uint32_t length,
    GxFlows *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, media_component_number, buf, length, offset );
    UNPACK_LIST_BASIC( data, flow_number, uint32_t, buf, length, offset );
    UNPACK_LIST_BASIC( data, content_version, uint64_t, buf, length, offset );
    UNPACK_BASIC( data, final_unit_action, buf, length, offset );
    UNPACK_BASIC( data, media_component_status, buf, length, offset );

    return *offset <= length;
}

/*
*
*       Fun:    unpackGxUserCsgInformation
*
*       Desc:   Unpack the specified buffer into GxUserCsgInformation
*
*       Ret:    0
*
*       Notes:  None
*
*       File:   gx_pack.c
*
*
*
*        User-CSG-Information ::= <AVP Header: 2319>
*              { CSG-Id }
*              { CSG-Access-Mode }
*              [ CSG-Membership-Indication ]
*/
static int unpackGxUserCsgInformation
(
    unsigned char *buf,
    uint32_t length,
    GxUserCsgInformation *data,
    uint32_t *offset
)
{
    UNPACK_PRESENCE( data, presence, buf, length, offset );
    UNPACK_BASIC( data, csg_id, buf, length, offset );
    UNPACK_BASIC( data, csg_access_mode, buf, length, offset );
    UNPACK_BASIC( data, csg_membership_indication, buf, length, offset );

    return *offset <= length;
}

