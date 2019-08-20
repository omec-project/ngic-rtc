#include <stdint.h>

#include "gx.h"

/*
*
*       Fun:    gx_send_cca
*
*       Desc:
*
*       Ret:
*
*       Notes:  None
*
*       File:   gx_cca.c
*
*/
int gx_send_cca(struct msg *rqst, void *data)
{
   int ret = FD_REASON_OK;
   struct avp *avp = NULL;
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
*       Fun:    gx_cca_cb
*
*       Desc:   CMDNAME call back
*
*       Ret:    0
*
*       File:   gx_cca.c
*
    The Credit-Control-Answer (CCA) command, indicated by
    the Command-Code field set to 272 and the 'R'
    bit cleared in the Command Flags field, is sent to/from MME or SGSN.
*
    Credit-Control-Answer ::= <Diameter Header: 272, PXY, 16777238>
          < Session-Id >
          [ DRMP ]
          { Auth-Application-Id }
          { Origin-Host }
          { Origin-Realm }
          [ Result-Code ]
          [ Experimental-Result ]
          { CC-Request-Type }
          { CC-Request-Number }
          [ OC-Supported-Features ]
          [ OC-OLR ]
      *   [ Supported-Features ]
          [ Bearer-Control-Mode ]
      *   [ Event-Trigger ]
          [ Event-Report-Indication ]
          [ Origin-State-Id ]
      *   [ Redirect-Host ]
          [ Redirect-Host-Usage ]
          [ Redirect-Max-Cache-Time ]
      *   [ Charging-Rule-Remove ]
      *   [ Charging-Rule-Install ]
          [ Charging-Information ]
          [ Online ]
          [ Offline ]
      *   [ QoS-Information ]
          [ Revalidation-Time ]
          [ Default-EPS-Bearer-QoS ]
          [ Default-QoS-Information ]
          [ Bearer-Usage ]
      *   [ Usage-Monitoring-Information ]
      *   [ CSG-Information-Reporting ]
          [ User-CSG-Information ]
          [ PRA-Install ]
          [ PRA-Remove ]
          [ Presence-Reporting-Area-Information ]
          [ Session-Release-Cause ]
          [ NBIFOM-Support ]
          [ NBIFOM-Mode ]
          [ Default-Access ]
          [ RAN-Rule-Support ]
      *   [ Routing-Rule-Report ]
      * 4 [ Conditional-Policy-Information ]
          [ Removal-Of-Access ]
          [ IP-CAN-Type ]
          [ Error-Message ]
          [ Error-Reporting-Host ]
          [ Failed-AVP ]
      *   [ Proxy-Info ]
      *   [ Route-Record ]
      *   [ Load ]
      *   [ AVP ]

*/
int gx_cca_cb
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
   GxCCA *cca = NULL;

#if 0
FD_DUMP_MESSAGE(rqst);
#endif

   /* retrieve the original query associated with the answer */
   CHECK_FCT(fd_msg_answ_getq (ans, &qry));

   /* allocate the cca message */
   cca = (GxCCA*)malloc(sizeof(*cca));

   memset((void*)cca, 0, sizeof(*cca));

   ret = gx_cca_parse(*msg, cca);
   if (ret != FD_REASON_OK)
      goto err;

   /*
    *  TODO - Add request processing code
    */

   gx_cca_free(cca);
   goto fini2;

err:
   gx_cca_free(cca);
   free(cca);
   goto fini2;

fini1:

fini2:
   FDCHECK_MSG_FREE(*msg);
   *msg = NULL;
   return 0;
}
