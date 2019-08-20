#include <unistd.h>
#include <signal.h>

#include "gx.h"

extern int gx_app_sock;
extern struct sockaddr_un server_sockaddr;
extern struct sockaddr_un client_sockaddr;
int unixsock();

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

int main(int argc, char **argv)
{
	int rval = 0;
	const char *fdcfg = "gx.conf";

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

	printf("Opening unix socket...");
	if ( (rval = unixsock()) != FD_REASON_OK )
	{
		printf("Failure (%d) in unixsock()\n", rval);
		return 1;
	}
	printf("complete\n");

	while (!done)
		sleep(1);

	fd_core_shutdown();
	fd_core_wait_shutdown_complete();

	return 0;
}
