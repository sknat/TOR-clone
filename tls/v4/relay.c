/*
	relay - PORC relay

	The PORC relay transfers a stream to another relay or to the target.
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "config.h"
#include "mytls.h"
#include "mytcp.h"

// BUG : Connot use global variable xcred.
gnutls_certificate_credentials_t xcred_serv;

static gnutls_priority_t priority_cache;
static struct sockaddr_in sockaddr_server;
static int listen_socket_descriptor;


/*
	do_proxy_relay - Do proxy between a clear connection and a secure connection.
*/
void do_proxy_relay(int target_socket_descriptor, PORC_STREAM *porc_stream) {
	int fd1 = target_socket_descriptor;
	int fd2 = porc_stream->socket_descriptor;
	fd_set read_fds;
	int result;
	int nfds = fd1+1;
	char buffer[BUF_SIZE+1];

	if (fd2>fd1) {
		nfds = fd2+1;
	}

	FD_ZERO (&read_fds);
	FD_SET (fd1, &read_fds);
	FD_SET (fd2, &read_fds);

	while((result = select(nfds, &read_fds, 0, 0, 0)) > 0) {
		if (FD_ISSET (fd1, &read_fds)) {
			int recvd = recv(fd1, buffer, BUF_SIZE, 0);
			if(recvd <= 0) {
				printf ("Stop (100)\n");
				return;
			}
			buffer [recvd] = '\0';
			printf ("Receiving from target (%d bytes) : %s\n", recvd, buffer);
			gnutls_record_send(porc_stream->session, buffer, recvd);
		}
		if (FD_ISSET (fd2, &read_fds)) {
			int recvd = gnutls_record_recv(porc_stream->session, buffer, BUF_SIZE);
			if(recvd <= 0) {
				printf ("Stop (200)\n");
				return;
			}
			buffer [recvd] = '\0';
			printf ("Receiving from client (%d bytes) : %s\n", recvd, buffer);
			send(fd1, buffer, recvd, 0);
		}

		FD_ZERO (&read_fds);
		FD_SET (fd1, &read_fds);
		FD_SET (fd2, &read_fds);
	}

	gnutls_bye (porc_stream->session, GNUTLS_SHUT_WR);
	close (porc_stream->socket_descriptor);
	gnutls_deinit (porc_stream->session);
}

/*
	handle_connection - Sets up a PORC connection and starts the proxy function.
*/
void *handle_connection(void *arg) {
	int client_socket_descriptor = (int)arg;
	gnutls_session_t session;
	int ret;
	PORC_HANDSHAKE_REQUEST porc_handshake_request;
	PORC_HANDSHAKE_RESPONSE porc_handshake_response;
	int target_socket_descriptor;
	PORC_STREAM porc_stream;

	gnutls_init (&session, GNUTLS_SERVER);
	gnutls_priority_set (session, priority_cache);
	gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred_serv);
	gnutls_certificate_server_set_request (session, GNUTLS_CERT_IGNORE);

	gnutls_transport_set_int (session, client_socket_descriptor);
	do {
		ret = gnutls_handshake (session);
	}
	while (ret < 0 && gnutls_error_is_fatal (ret) == 0);

	if (ret < 0) {
		close (client_socket_descriptor);
		gnutls_deinit (session);
		fprintf (stderr, "*** Handshake has failed (%s)\n\n", gnutls_strerror (ret));
		return NULL;
	}
	printf ("- Handshake was completed\n");

	if (gnutls_record_recv (session, (char *)&porc_handshake_request, sizeof (porc_handshake_request)) != sizeof (porc_handshake_request)) {
		close (client_socket_descriptor);
		gnutls_deinit (session);
		fprintf (stderr, "PORC handshake error (100)\n");
		return NULL;	
	}

	target_socket_descriptor = (int)connect_to_host(porc_handshake_request.ip, porc_handshake_request.port);
	if(target_socket_descriptor == (int)NULL) {
		fprintf (stderr, "Failed to connect to target.\n");
		return NULL;
	}

	porc_stream.ip = porc_handshake_request.ip;
	porc_stream.port = porc_handshake_request.port;
	porc_stream.session = session;
	porc_stream.socket_descriptor = client_socket_descriptor;

	porc_handshake_response.status = PORC_SUCCESS;
	if (gnutls_record_send (session, (char *)&porc_handshake_response, sizeof (porc_handshake_response))
		!= sizeof (porc_handshake_response))
	{
		close (client_socket_descriptor);
		gnutls_deinit (session);
		fprintf (stderr, "PORC handshake error (200)\n");
		return NULL;	
	}

	printf ("PORC handshake completed\n");

	do_proxy_relay (target_socket_descriptor, &porc_stream);

	printf ("Connection closed\n");

	close (target_socket_descriptor);

	return NULL;
}


/*
	main - Initializes a TLS server and starts a thread for every client.
*/
int main (void)
{
	int client_socket_descriptor;
	struct sockaddr_in sockaddr_client;
	socklen_t client_adress_length;
	char topbuf[512];

	if (mytls_server_init (&xcred_serv, &priority_cache, &listen_socket_descriptor, &sockaddr_server) != 0) {
		return -1;
	}

	client_adress_length = sizeof (sockaddr_client);
	for (;;) {
		client_socket_descriptor = accept (listen_socket_descriptor, (struct sockaddr *) &sockaddr_client, &client_adress_length);
		printf ("- connection from %s, port %d\n", inet_ntop (AF_INET, &sockaddr_client.sin_addr, topbuf, sizeof (topbuf)),
			ntohs(sockaddr_client.sin_port));

		pthread_t thread;
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		pthread_create(&thread, &attr, handle_connection, (void *)client_socket_descriptor);
	}
	close (listen_socket_descriptor);

	gnutls_certificate_free_credentials (xcred_serv);
	gnutls_priority_deinit (priority_cache);

	gnutls_global_deinit ();

	return 0;
}

