#include <stdint.h>
#include "gx.h"
#include "../../cp_app.h"
#include "../../ipc_api.h"

extern int g_gx_client_sock;

int unixsock();

/*TBD need to move this in freediameter generated code*/
/**
 * @brief Add element to freediameter message
 * ready
 * @param[in] val - AVP value to be added
 * @param[in] obj - Disctionary object
 * @param[in/out] msg_buf
 * @return int Sucess or failure code
 */
int
add_fd_msg(union avp_value *val, struct dict_object * obj,
		struct msg **msg_buf)
{
	struct avp *avp_val = NULL;

	CHECK_FCT_DO(fd_msg_avp_new(obj, 0, &avp_val), return -1);

	CHECK_FCT_DO(fd_msg_avp_setvalue(avp_val, val), return -1);

	CHECK_FCT_DO(fd_msg_avp_add(*msg_buf, MSG_BRW_LAST_CHILD, avp_val),
			return -1);

	return 0;
}

void
prep_rar_for_cp(gx_req_msg *req, struct session *sess, struct msg *rqst)
{
	struct avp *avp_ptr = NULL;
	struct avp_hdr *avp_hdr = NULL;
	unsigned char *sess_id= NULL;
	int sess_id_len;
	int ret = FD_REASON_OK;

	req->hdr = GX_RAR_MSG;
	fd_sess_getsid(sess, &sess_id, (size_t*)&sess_id_len);
	req->data.cp_rar.session_id.len = sess_id_len;
	memcpy(&req->data.cp_rar.session_id.val, sess_id, sess_id_len);

	fd_msg_search_avp(rqst, gxDict.avp_re_auth_request_type, &avp_ptr);
	if (NULL != avp_ptr) {
		fd_msg_avp_hdr(avp_ptr, &avp_hdr);
		req->data.cp_rar.re_auth_request_type = avp_hdr->avp_value->i32;
	}

	fd_msg_search_avp(rqst, gxDict.avp_origin_state_id, &avp_ptr);
	if (NULL != avp_ptr) {
		fd_msg_avp_hdr(avp_ptr, &avp_hdr);
		req->data.cp_rar.origin_state_id = avp_hdr->avp_value->u32;
	}

	fd_msg_search_avp(rqst, gxDict.avp_default_qos_information, &avp_ptr);
	if (NULL != avp_ptr) {

		struct avp *sub_avp = NULL;
		struct avp_hdr *element = NULL;

		CHECK_FCT_DO(fd_msg_avp_hdr(avp_ptr, &element), ret = -1);

		/*Find first sub child of Default Qos info*/
		CHECK_FCT_DO(fd_msg_browse(avp_ptr, MSG_BRW_FIRST_CHILD, &sub_avp, NULL),ret = -1);

		/*Lookup for sub element "Max Request Bandwidth UL/DL etc" in loop*/
		while (NULL != sub_avp) {

			fd_msg_avp_hdr(sub_avp, &element);

			if (NULL != element) {
				if(element->avp_code == 516) {
				/* Max BW UL*/
					req->data.cp_rar.default_qos_information.max_requested_bandwidth_ul =
						element->avp_value->u32;

				} else if (element->avp_code == 515){
				     /* Max BW DL*/
					req->data.cp_rar.default_qos_information.max_requested_bandwidth_dl =
						element->avp_value->u32;
				} else if (element->avp_code ==1028){
				     /* QCI*/
					req->data.cp_rar.default_qos_information.qos_class_identifier =
						element->avp_value->i32;
				}

				/*Iterate sub entries*/
				CHECK_FCT_DO(fd_msg_browse(sub_avp, MSG_BRW_NEXT, &sub_avp, NULL), ret=-1);
			}
		}
	}
	/*printf("ULBW [%u] DLBW[%u] \n", req->data.cp_rar.default_qos_information.max_requested_bandwidth_ul,
			req->data.cp_rar.default_qos_information.max_requested_bandwidth_dl);*/
}

/*
 *
 *       Fun:    gx_send_rar
 *
 *       Desc:
 *
 *       Ret:
 *
 *       Notes:  None
 *
 *       File:   gx_rar.c
 *
 */
int gx_send_rar(void *data)
{
	int rval = FD_REASON_OK;
	struct avp *avp = NULL;
	struct msg *msg = NULL;

#if 0
	/* create new session id */
	FDCHECK_FCT_2( aqfdCreateSessionId(ueCb) );
#endif

	/* construct the message */
	FDCHECK_MSG_NEW( gxDict.cmdRAR, msg, rval, goto err );

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
 *       Fun:    gx_rar_cb
 *
 *       Desc:   CMDNAME call back
 *
 *       Ret:    0
 *
 *       File:   gx_rar.c
 *
The Re-Auth-Request (RAR) command, indicated by
the Command-Code field set to 258 and the 'R'
bit set in the Command Flags field, is sent to/from MME or SGSN.
 *
Re-Auth-Request ::= <Diameter Header: 258, REQ, PXY, 16777238>
< Session-Id >
[ DRMP ]
{ Auth-Application-Id }
{ Origin-Host }
{ Origin-Realm }
{ Destination-Realm }
{ Destination-Host }
{ Re-Auth-Request-Type }
[ Session-Release-Cause ]
[ Origin-State-Id ]
[ OC-Supported-Features ]
 *   [ Event-Trigger ]
[ Event-Report-Indication ]
 *   [ Charging-Rule-Remove ]
 *   [ Charging-Rule-Install ]
[ Default-EPS-Bearer-QoS ]
 *   [ QoS-Information ]
[ Default-QoS-Information ]
[ Revalidation-Time ]
 *   [ Usage-Monitoring-Information ]
[ PCSCF-Restoration-Indication ]
 * 4 [ Conditional-Policy-Information ]
[ Removal-Of-Access ]
[ IP-CAN-Type ]
[ PRA-Install ]
[ PRA-Remove ]
 *   [ CSG-Information-Reporting ]
 *   [ Proxy-Info ]
 *   [ Route-Record ]
 *   [ AVP ]

*/
int gx_rar_cb
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
	GxRAR *rar = NULL;
	size_t len = 0;
	char buf[BUFFSIZE] = {0};
	int rc;
	gx_req_msg gx_req = {0};
	gx_resp_msg *resp = NULL;
	int bytes_recv = 0;
	struct avp *avp_ptr = NULL;;
	union avp_value val;

	*msg = NULL;
#if 1
	FD_DUMP_MESSAGE(rqst);
#endif

	prep_rar_for_cp(&gx_req, sess, rqst);
	/* printf("ULBW [%u] DLBW[%u] \n", gx_req.data.cp_rar.default_qos_information.max_requested_bandwidth_ul,
		gx_req.data.cp_rar.default_qos_information.max_requested_bandwidth_dl); */

	send_to_ipc_channel(g_gx_client_sock, (char *)&gx_req);

	/* allocate the rar message */
	rar = (GxRAR*)malloc(sizeof(*rar));

	memset((void*)rar, 0, sizeof(*rar));

	ret = gx_rar_parse(rqst, rar);
	if (ret != FD_REASON_OK){
		goto err;
	}

	/*
	 *  TODO - Add request processing code
	 */
	FDCHECK_MSG_NEW_ANSWER_FROM_REQ( fd_g_config->cnf_dict, ans, ret, goto err );
	FDCHECK_MSG_ADD_ORIGIN( ans, ret, goto err );
	FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_result_code, ans, MSG_BRW_LAST_CHILD, 2001, ret, goto err );

	bytes_recv = recv_from_ipc_channel(g_gx_client_sock, buf);
	if(bytes_recv > 0){
		resp = (gx_resp_msg *)buf;
		printf("session id [%s] ulBw [%d] dlBW[%d]\n",resp->data.cp_raa.session_id.val,
				resp->data.cp_raa.default_qos_information.max_requested_bandwidth_ul,
				resp->data.cp_raa.default_qos_information.max_requested_bandwidth_dl);

		/*Updated session-id in ans */
		fd_msg_search_avp(ans, gxDict.avp_session_id, &avp_ptr);
		if (NULL != avp_ptr) {
			val.os.data = resp->data.cp_raa.session_id.val;
			val.os.len = resp->data.cp_raa.session_id.len;
			CHECK_FCT_DO(fd_msg_avp_setvalue(avp_ptr, &val), ret = FD_REASON_AVP_SETVALUE_FAIL; goto err);
		}

		/* Adding Qos params */
		CHECK_FCT_DO(fd_msg_avp_new(gxDict.avp_default_qos_information, 0, &avp_ptr), return -1);
		CHECK_FCT_DO(fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp_ptr), return -1);

		val.u32 = resp->data.cp_raa.default_qos_information.max_requested_bandwidth_ul;
		val.os.len = sizeof(resp->data.cp_raa.default_qos_information.max_requested_bandwidth_ul);
		add_fd_msg(&val,gxDict.avp_max_requested_bandwidth_ul ,(struct msg**)&avp_ptr);

		val.u32 = resp->data.cp_raa.default_qos_information.max_requested_bandwidth_dl;
		val.os.len = sizeof(resp->data.cp_raa.default_qos_information.max_requested_bandwidth_dl);
		add_fd_msg(&val,gxDict.avp_max_requested_bandwidth_dl ,(struct msg**)&avp_ptr);

		val.i32 = resp->data.cp_raa.default_qos_information.qos_class_identifier;
		val.os.len = sizeof(resp->data.cp_raa.default_qos_information);
		add_fd_msg(&val, gxDict.avp_qos_class_identifier ,(struct msg**)&avp_ptr);
	}

#if 1
	FD_DUMP_MESSAGE(ans);
#endif
	FDCHECK_MSG_SEND( ans, NULL, NULL, ret, goto err );

	goto fini1;

err:
	printf("Error (%d) while processing RAR\n", ret);
	free(rar);
	goto fini2;

fini1:

fini2:
	gx_rar_free(rar);
	return ret;
}

