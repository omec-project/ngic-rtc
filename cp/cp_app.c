#include "cp_app.h"
#include "ipc_api.h"

int g_cp_sock = 0;
/*
This function fills the required RAA parameter in resp msg
*/
void
prep_gx_resp_msg(gx_resp_msg *resp)
{
	char qos_name[BUFFSIZE] = "temp";

	resp->hdr = GX_RAA_MSG;
	resp->data.cp_raa.session_id.len = 3;
	memcpy(resp->data.cp_raa.session_id.val, "123", resp->data.cp_raa.session_id.len);

	resp->data.cp_raa.default_qos_information.presence.qos_class_identifier = 1;
	resp->data.cp_raa.default_qos_information.presence.max_requested_bandwidth_ul = 1;
	resp->data.cp_raa.default_qos_information.presence.max_requested_bandwidth_dl = 1;
	resp->data.cp_raa.default_qos_information.presence.default_qos_name = 1;
	resp->data.cp_raa.default_qos_information.max_requested_bandwidth_ul = 12;
	resp->data.cp_raa.default_qos_information.max_requested_bandwidth_dl = 10;
	resp->data.cp_raa.default_qos_information.default_qos_name.len = 4;

	memcpy(resp->data.cp_raa.default_qos_information.default_qos_name.val, qos_name, strlen(qos_name));
}

/*
This function Handles the RAR msg received from PCEF
*/
void
handle_gx_rar(RAR *cp_rar)
{
	/*Need to handle cp_rar*/
	printf("Gx Session Id [%s]\n",cp_rar->session_id.val);
	/*printf("Session Id [%s] re_auth_req_type [%d] org_st [%u] maxBwUl[%u] maxBwdl[%u] QCI[%d] \n",
			cp_rar->session_id.val, cp_rar->re_auth_request_type, cp_rar->origin_state_id,
			cp_rar->default_qos_information.max_requested_bandwidth_ul,
			cp_rar->default_qos_information.max_requested_bandwidth_dl,
			cp_rar->default_qos_information.qos_class_identifier);*/
}

/*
This function Handles the msgs received from PCEF
*/
void
gx_msg_handler(void *buf)
{
	gx_req_msg *req = (gx_req_msg*)buf;
	switch (req->hdr){
		case GX_RAR_MSG:
			handle_gx_rar(&(req->data.cp_rar));
			break;

		default:
			printf( "Unknown message received from Gx app - %d\n",
					req->hdr);
	}
}

int
msg_handler(int sock )
{
	struct sockaddr_un gx_app_sockaddr = {0};
	char recv_buf[BUFFSIZE] = {0};
	char send_buf[BUFFSIZE] = {0};
	int bytes_recv = 0, gx_app_sock = 0, done = 0;

	if ( (gx_app_sock  = accept_from_ipc_channel( sock, gx_app_sockaddr)) == -1) {
		perror("accept error");
		return 1;
	}

	get_peer_name(gx_app_sock, gx_app_sockaddr);

	while (!done){
		bytes_recv = recv_from_ipc_channel(gx_app_sock, recv_buf);
		if(bytes_recv >= 0 ) {

			gx_msg_handler((void *)recv_buf);

			gx_resp_msg *resp = malloc(sizeof(gx_resp_msg));
			prep_gx_resp_msg(resp);
			memcpy(send_buf, (char*)resp, sizeof(gx_resp_msg));

			send_to_ipc_channel(gx_app_sock, send_buf);
		}else{
			printf("[%d] DATA RECEIVED\n ", bytes_recv);
			done = 1;
		}
	}

	return 0;
}

void
start_cp_app(void )
{

	struct sockaddr_un cp_app_sockaddr = {0};

	g_cp_sock = create_ipc_channel();

	bind_ipc_channel(g_cp_sock, cp_app_sockaddr, SERVER_PATH);

	listen_ipc_channel(g_cp_sock);

	return ;
}


