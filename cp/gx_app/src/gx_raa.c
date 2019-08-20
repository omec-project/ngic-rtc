#include <stdint.h>

#include "gx.h"

/*
*
*       Fun:    gx_send_raa
*
*       Desc:
*
*       Ret:
*
*       Notes:  None
*
*       File:   gx_raa.c
*
*/
int gx_send_raa(struct msg *rqst, void *data)
{
   int ret = FD_REASON_OK;
   struct msg *ans = rqst;

   /* construct the message */
   FDCHECK_MSG_NEW_ANSWER_FROM_REQ( fd_g_config->cnf_dict, ans, ret, goto err );

   FDCHECK_MSG_ADD_ORIGIN( ans, ret, goto err );
   FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_destination_host, ans, MSG_BRW_LAST_CHILD, fd_g_config->cnf_diamid, fd_g_config->cnf_diamid_len, ret, goto err );
   FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_destination_realm, ans, MSG_BRW_LAST_CHILD, fd_g_config->cnf_diamrlm, fd_g_config->cnf_diamrlm_len, ret, goto err );

   //TODO - FILL IN HERE
#if 0
FD_DUMP_MESSAGE(msg);
#endif

   /* send the message */
   FDCHECK_MSG_SEND( ans, NULL, NULL, ret, goto err );
   goto fini;

err:
   /* free the message since an error occurred */
   FDCHECK_MSG_FREE(ans);

fini:
   return ret;
}

/*
*
*       Fun:    gx_raa_cb
*
*       Desc:   CMDNAME call back
*
*       Ret:    0
*
*       File:   gx_raa.c
*
    The Re-Auth-Answer (RAA) command, indicated by
    the Command-Code field set to 258 and the 'R'
    bit cleared in the Command Flags field, is sent to/from MME or SGSN.
*
    Re-Auth-Answer ::= <Diameter Header: 258, PXY, 16777238>
          < Session-Id >
          [ DRMP ]
          { Origin-Host }
          { Origin-Realm }
          [ Result-Code ]
          [ Experimental-Result ]
          [ Origin-State-Id ]
          [ OC-Supported-Features ]
          [ OC-OLR ]
          [ IP-CAN-Type ]
          [ RAT-Type ]
          [ AN-Trusted ]
      * 2 [ AN-GW-Address ]
          [ 3GPP-SGSN-MCC-MNC ]
          [ 3GPP-SGSN-Address ]
          [ 3GPP-SGSN-Ipv6-Address ]
          [ RAI ]
          [ 3GPP-User-Location-Info ]
          [ User-Location-Info-Time ]
          [ NetLoc-Access-Support ]
          [ User-CSG-Information ]
          [ 3GPP-MS-TimeZone ]
          [ Default-QoS-Information ]
      *   [ Charging-Rule-Report ]
          [ Error-Message ]
          [ Error-Reporting-Host ]
          [ Failed-AVP ]
      *   [ Proxy-Info ]
      *   [ AVP ]

*/
int gx_raa_cb
(
   struct msg ** msg,
   struct avp * pavp,
   struct session * sess,
   void * data,
   enum disp_action * act
)
{
   int ret = FD_REASON_OK;
   struct msg *ans = *msg;
   struct msg *qry = NULL;
   GxRAA *raa = NULL;

#if 0
FD_DUMP_MESSAGE(rqst);
#endif

   /* retrieve the original query associated with the answer */
   CHECK_FCT(fd_msg_answ_getq (ans, &qry));

   /* allocate the raa message */
   raa = (GxRAA*)malloc(sizeof(*raa));

   memset((void*)raa, 0, sizeof(*raa));

   ret = gx_raa_parse(*msg, raa);
   if (ret != FD_REASON_OK)
      goto err;

   /*
    *  TODO - Add request processing code
    */

   gx_raa_free(raa);
   goto fini2;

err:
   gx_raa_free(raa);
   free(raa);
   goto fini2;

//fini1:

fini2:
   FDCHECK_MSG_FREE(*msg);
   *msg = NULL;
   return 0;
}
