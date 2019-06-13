#include "../../cp_app.h"
#include "../../ipc_api.h"

int g_gx_client_sock = 0;

int unixsock()
{
	struct sockaddr_un gx_app_sockaddr = {0};
	struct sockaddr_un cp_app_sockaddr = {0};

	g_gx_client_sock = create_ipc_channel();

	bind_ipc_channel( g_gx_client_sock, gx_app_sockaddr, CLIENT_PATH );

	connect_to_ipc_channel( g_gx_client_sock, cp_app_sockaddr, SERVER_PATH );

	return 0;
}
