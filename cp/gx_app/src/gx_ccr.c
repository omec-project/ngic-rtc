#include <stdint.h>

#include "gx.h"

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
   struct avp *avp = NULL;
   struct msg *msg = NULL;

#if 0
   /* create new session id */
   FDCHECK_FCT_2( aqfdCreateSessionId(ueCb) );
#endif

   /* construct the message */
   FDCHECK_MSG_NEW( gxDict.cmdCCR, msg, rval, goto err );

#if 0
   FDCHECK_MSG_ADD_AVP_STR( gxDict.avp_session_id, msg, MSG_BRW_LAST_CHILD, ueCb->ueCtxt.ueHssCtxt.sessId );
#endif
   FDCHECK_MSG_ADD_ORIGIN( msg, rval, goto err );
   FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_destination_host, msg, MSG_BRW_LAST_CHILD, fd_g_config->cnf_diamid, fd_g_config->cnf_diamid_len, rval, goto err );
   FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_destination_realm, msg, MSG_BRW_LAST_CHILD, fd_g_config->cnf_diamrlm, fd_g_config->cnf_diamrlm_len, rval, goto err );
#if 0
   FDCHECK_MSG_ADD_AVP_STR( gxDict.avp_user_name, msg, MSG_BRW_LAST_CHILD, imsi );
#endif

   //TODO - FILL IN HERE
#if 0
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
