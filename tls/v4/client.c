/*
	client - PORC client

	The PORC client acts is a SOCKSv4 proxy between client seeking for a secure and anonymous connexion and a PORC relay.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"
#include "mytls.h"
#include "socks.h"

/*
	new_stream - new_client function for the PORC client.

	Creates and returns a pointer to a new PORC_STREAM structure for the new client.
*/
void *new_stream(uint32_t ip, uint16_t port) {
	int socket_descriptor;
	int ret;
	gnutls_session_t session;
	PORC_HANDSHAKE_REQUEST porc_handshake_request;
	PORC_HANDSHAKE_RESPONSE porc_handshake_response;
	PORC_STREAM *porc_stream;

	ret = mytls_client_session_init (inet_addr(RELAY_IP), htons(RELAY_PORT), &session, &socket_descriptor);
	if (ret < 0) {
		fprintf (stderr, "Error in mytls_client_session_init()\n");
		return NULL;
	}

	porc_handshake_request.ip = ip;
	porc_handshake_request.port = port;

	if (gnutls_record_send (session, (char *)&porc_handshake_request, sizeof (porc_handshake_request)) != sizeof (porc_handshake_request)) {
		fprintf (stderr, "PORC handshake error (100)\n");
		close (socket_descriptor);
		gnutls_deinit (session);
		return NULL;	
	}

	if (gnutls_record_recv (session, (char *)&porc_handshake_response, sizeof (porc_handshake_response))
		!= sizeof (porc_handshake_response))
	{
		fprintf (stderr, "PORC handshake error (200)\n");
		close (socket_descriptor);
		gnutls_deinit (session);
		return NULL;	
	}

	if (porc_handshake_response.status != PORC_SUCCESS) {
		fprintf (stderr, "PORC handshake error (300)\n");
		close (socket_descriptor);
		gnutls_deinit (session);
		return NULL;	
	}

	printf ("PORC Handshake completed\n");

	porc_stream = malloc (sizeof(PORC_STREAM));
	porc_stream->ip = ip;
	porc_stream->port = port;
	porc_stream->session = session;
	porc_stream->socket_descriptor = socket_descriptor;

	return porc_stream;
}

/*
	do_proxy_crypto - do_proxy function for the PORC client.

	Do proxy between a clear connection and a secure connection.
*/
void do_proxy_crypto(int client_socket_descriptor, void *stream2) {
	int fd1 = client_socket_descriptor;
	PORC_STREAM *porc_stream = (PORC_STREAM *)stream2;
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
			printf ("Receiving from client (%d bytes) : %s\n", recvd, buffer);
			gnutls_record_send(porc_stream->session, buffer, recvd);
		}
		if (FD_ISSET (fd2, &read_fds)) {
			int recvd = gnutls_record_recv(porc_stream->session, buffer, BUF_SIZE);
			if(recvd <= 0) {
				printf ("Stop (200)\n");
				return;
			}
			buffer [recvd] = '\0';
			printf ("Receiving from relay (%d bytes) : %s\n", recvd, buffer);
			send(fd1, buffer, recvd, 0);
		}

		FD_ZERO (&read_fds);
		FD_SET (fd1, &read_fds);
		FD_SET (fd2, &read_fds);
	}

	gnutls_bye (porc_stream->session, GNUTLS_SHUT_WR);
	close (porc_stream->socket_descriptor);
	gnutls_deinit (porc_stream->session);
	free (porc_stream);
}


int main () {
	int ret;

	if ((ret=mytls_client_global_init (&xcred))<0) {
		printf ("Error in mytls_client_global_init()\n");
		return -1;
	}

	new_client = *new_stream;
	do_proxy = *do_proxy_crypto;

	proxy_socksv4 (CLIENT_PORT);

	gnutls_certificate_free_credentials (xcred);
	gnutls_global_deinit ();

	return 0;
}

