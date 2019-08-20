#ifndef CP_APP_H_
#define CP_APP_H_

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdbool.h>

#define GX_SESSION_ID_LEN      255
#define DEFAULT_QOS_NAME_LEN   255

#define SERVER_PATH "/usr/sock_server"
#define CLIENT_PATH "/usr/sock_client"

#define BUFFSIZE 1024
#define BACKLOG  100
#define LENGTH sizeof(struct sockaddr_un)

extern int g_cp_sock;

#pragma pack(1)

enum e_BUF_HDR {
	GX_RAR_MSG,
	GX_RAA_MSG,
	GX_CCR_MSG,
	GX_CCA_MSG,
};

typedef struct SessionId {
	unsigned int len;
	unsigned char val[GX_SESSION_ID_LEN + 1];
} SessionId;

typedef struct DefaultQosInformationPresence {
	unsigned int qos_class_identifier       : 1;
	unsigned int max_requested_bandwidth_ul : 1;
	unsigned int max_requested_bandwidth_dl : 1;
	unsigned int default_qos_name           : 1;
} DefaultQosInformationPresence;

typedef struct DefaultQosName {
	unsigned int len;
	unsigned char val[DEFAULT_QOS_NAME_LEN + 1];
} DefaultQosName;

typedef struct DefaultQosInformation {
	DefaultQosInformationPresence presence;
	signed int qos_class_identifier;
	unsigned int max_requested_bandwidth_ul;
	unsigned int max_requested_bandwidth_dl;
	DefaultQosName default_qos_name;
} DefaultQosInformation;

typedef struct RAA{
	SessionId session_id;
	DefaultQosInformation default_qos_information;
}RAA;

typedef struct RAR{
	signed int re_auth_request_type;
	unsigned int origin_state_id;
	SessionId session_id;
	DefaultQosInformation default_qos_information;
}RAR;

typedef struct gx_req_msg {
	enum e_BUF_HDR hdr;
	union req_data {
		RAR cp_rar;
	}data;
}gx_req_msg;

typedef struct gx_resp_msg {
	enum e_BUF_HDR hdr;
	union resp_data {
		RAA cp_raa;
	}data;
}gx_resp_msg;

#pragma pack()

void
prep_gx_resp_msg(gx_resp_msg *resp);

void
handle_gx_rar(RAR *cp_rar);

void
gx_msg_handler(void *buf);

int
msg_handler(int sock );

void
start_cp_app( void );

#endif /* CP_APP_H_ */
