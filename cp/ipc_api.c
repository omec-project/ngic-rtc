#include "cp_app.h"
#include "ipc_api.h"

int
create_ipc_channel( void )
{
	/* STREAM - BiDirectional
	  DATAGRAM - uniDirectional */
	int sock ;
	sock = socket( AF_UNIX, SOCK_STREAM, 0);
	if ( sock == -1 ){
		printf("SOCKET ERROR = %s", strerror(errno));
		exit(1);
	}
	return sock;
}

void
connect_to_ipc_channel(int sock, struct sockaddr_un sock_addr, const char *path)
{
	int rc = 0;

	socklen_t  len = LENGTH;
	sock_addr.sun_family = AF_UNIX;

	chmod( path, 755 );

	strncpy(sock_addr.sun_path, path, strlen(path));

	rc = connect( sock, (struct sockaddr *) &sock_addr, len);
	if ( rc == -1){
		printf( "CONNECT ERROR = %s\n", strerror(errno));
		close_ipc_channel( sock );
		exit(1);
	}
	printf( "gx_app cp_app connected successfuly \n" );
}

void
bind_ipc_channel(int sock, struct sockaddr_un sock_addr,const char *path)
{
	socklen_t  len = LENGTH;
	int rc;
	chmod( path, 755 );

	sock_addr.sun_family = AF_UNIX;
	strncpy(sock_addr.sun_path, path, strlen(path));

	unlink(path);
	rc =  bind( sock, (struct sockaddr *) &sock_addr, len);
	if( rc != 0 ){
		printf("BIND ERROR = %s", strerror(errno));
		close_ipc_channel(sock);
		exit(1);
	}
}

int
accept_from_ipc_channel(int sock, struct sockaddr_un sock_addr)
{
	socklen_t len ;
	len = sizeof(sock_addr);
	int gx_app_sock;
	while(1) {
		gx_app_sock = accept( sock, (struct sockaddr *) &sock_addr, &len);
		if ( gx_app_sock == -1 ){
			if( errno != EINTR ){
				printf("ACCEPT ERROR: %s\n",strerror(errno));
				close_ipc_channel(sock);
				exit(1);
			}
		}else {
			printf( "Succesfully Accepted gx_app \n" );
			return gx_app_sock;
		}
	}
}

void
listen_ipc_channel( int sock )
{
	if( listen(sock, BACKLOG) == -1){
		printf("LISTEN ERROR: %s\n", strerror(errno));
		close_ipc_channel(sock);
		exit(1);
	}
	printf("socket listening...\n");
}

void
get_peer_name(int sock, struct sockaddr_un sock_addr)
{
	socklen_t  len = LENGTH;
	if( getpeername( sock, (struct sockaddr *) &sock_addr, &len) == -1) {
		if(errno != EINTR)
		{
			printf("GETPEERNAME ERROR: %s\n", strerror(errno));
			close_ipc_channel(sock);
			exit(1);
		}
	} else {
		printf("Client socket filepath: %s\n", sock_addr.sun_path);
	}

}

int
recv_from_ipc_channel(int sock, char *buf)
{
	int bytes_recv = 0;
	for(;;){
		bytes_recv = recv(sock, buf, BUFFSIZE, 0) ;
		if ( bytes_recv <= 0 ){

			if(errno != EINTR){
				printf("RECV ERROR: %s, %d\n", strerror(errno), errno);
				close_ipc_channel(sock);
				exit(1);
			}else {
				//printf("Data not received %s  %d\n", strerror(errno), errno);
				continue;
			}
		} else {
			printf("Data Received \n");
			return bytes_recv;
		}
	}
	return bytes_recv;
}

void
send_to_ipc_channel(int sock, char *buf)
{
	if( send(sock, buf, BUFFSIZE, 0) <= 0){
		if(errno != EINTR){
			printf("SEND ERROR: %s", strerror(errno));
			close_ipc_channel(sock);
			exit(1);
		}
	} else {
		printf("Data Sent \n");
	}

}

void
close_ipc_channel(int sock)
{
	    printf( "Closing socket [%d]\n", sock );
		close(sock);
}

