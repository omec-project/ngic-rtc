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

#include <unistd.h>
#include <signal.h>

#include "gx.h"

extern int gx_app_sock;
extern int g_gx_client_sock;

int done = 0;

void signal_handler(int sig)
{
	done = 1;
}

int fdinit(const char *fdcfg)
{
	/* Initialize the core freeDiameter library */
	CHECK_FCT_DO( fd_core_initialize(), return FD_REASON_CORE_INIT_FAIL );
	/* Parse the configuration file */
	CHECK_FCT_DO( fd_core_parseconf(fdcfg), return FD_REASON_PARSECONF_FAIL );
	return FD_REASON_OK;
}

int fdstart()
{
	/* Start freeDiameter */
	CHECK_FCT_DO( fd_core_start(), return FD_REASON_PARSECONF_FAIL );
	return FD_REASON_OK;
}

static int
parse_fd_config(const char *filename, char *peer_name)
{
	FILE *gx_fd = NULL;
	char data[1024] = {0};
	char *token = NULL;
	char *token1 = NULL;
	size_t str_len = 0;

	if((gx_fd = fopen(filename, "r")) <= 0) {
		fprintf(stderr, "ERROR :[ %s ] unable to read [ %s ] file\n" ,__func__ ,filename);
		return -1;
	}
	fseek(gx_fd, 0L, SEEK_SET);

	while((fgets(data, 256, gx_fd)) != NULL) {
		if(data[0]  == '#') {
			continue;
		}
		if(strstr(data, CONNECTPEER) != NULL) {
				token = strchr(data, '"');
				if(token != NULL){
					token1 = strchr(token+1, '"');
					str_len = token1 - token;
					memcpy(peer_name, token+1, str_len-1);
				}
				fclose(gx_fd);
				return 0;
		}

	}
	fclose(gx_fd);
	return -1;
}

int main(int argc, char **argv)
{
	int rval = 0;
	const char *fdcfg = "gx.conf";
	char peer_name[256] = {0};

	printf("Registering signal handler...");
	if ( signal(SIGINT, signal_handler) == SIG_ERR )
	{
		printf("Cannot catch SIGINT\n");
		return 1;
	}
	printf("complete\n");

	printf("Initializing freeDiameter...");
	if ( (rval = fdinit(fdcfg)) != FD_REASON_OK )
	{
		printf("Failure (%d) in fdinit()\n", rval);
		return 1;
	}
	printf("complete\n");

	printf("Calling gxInit()...");
	if ( (rval = gxInit()) != FD_REASON_OK )
	{
		printf("Failure (%d) in gxInit()\n", rval);
		return 1;
	}
	printf("complete\n");

	printf("Calling gxRegistger()...");
	if ( (rval = gxRegister()) != FD_REASON_OK )
	{
		printf("Failure (%d) in gxRegister()\n", rval);
		return 1;
	}
	printf("complete\n");

	printf("Starting freeDiameter...");
	if ( (rval = fdstart()) != FD_REASON_OK )
	{
		printf("Failure (%d) in fdstart()\n", rval);
		return 1;
	}
	printf("complete\n");
	if(parse_fd_config(fdcfg, peer_name) < 0 ) {
		fprintf(stderr, "unable to read [ %s ] file \n",fdcfg);
		return -1;
	}

	printf("Waiting to connect to [%s] \n", peer_name);
	while(1){
		struct peer_hdr *peer;
		sleep(1);
		if ( ! fd_peer_getbyid(peer_name, strlen(peer_name), 1, &peer ) ){
			int state = fd_peer_get_state(peer);
			if ( state == STATE_OPEN || state == STATE_OPEN_NEW ) {
				break;
			}
		}
		if(done == 1) {
			close_ipc_channel(g_gx_client_sock);
			fd_core_shutdown();
			fd_core_wait_shutdown_complete();
			return -1;
		}
	}
	printf("complete\n");

	printf("Opening unix socket...");
	if ( (rval = unixsock()) != FD_REASON_OK )
	{
		printf("Failure (%d) in unixsock()\n", rval);
		return 1;
	}
	printf("complete\n");

	while (!done)
		sleep(1);

	close_ipc_channel(g_gx_client_sock);
	fd_core_shutdown();
	fd_core_wait_shutdown_complete();

	return 0;
}
