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

static gnutls_certificate_credentials_t xcred;
static gnutls_priority_t priority_cache;
static struct sockaddr_in sockaddr_server;
static int listen_socket_descriptor;

static void *handle_connection(void *arg);

int main (void)
{
	int client_socket_descriptor;
	int ret;
	struct sockaddr_in sockaddr_client;
	socklen_t client_adress_length;
	char topbuf[512];
	int optval = 1;

	if (mytls_server_init (&xcred, &priority_cache, &listen_socket_descriptor, &sockaddr_server) != 0) {
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

	gnutls_certificate_free_credentials (xcred);
	gnutls_priority_deinit (priority_cache);

	gnutls_global_deinit ();

	return 0;
}

void *handle_connection(void *arg) {
	int client_socket_descriptor = (int)arg;
	gnutls_session_t session;
	int ret;
	char buffer[MAX_BUF + 1];

	gnutls_init (&session, GNUTLS_SERVER);
	gnutls_priority_set (session, priority_cache);
	gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);
	gnutls_certificate_server_set_request (session, GNUTLS_CERT_IGNORE);

	gnutls_transport_set_int (session, client_socket_descriptor);
	do {
		ret = gnutls_handshake (session);
	}
	while (ret < 0 && gnutls_error_is_fatal (ret) == 0);

	if (ret < 0) {
		close (client_socket_descriptor);
		gnutls_deinit (session);
		fprintf (stderr, "*** Handshake has failed (%s)\n\n",
			gnutls_strerror (ret));
		return;
	}
	printf ("- Handshake was completed\n");

	for (;;) {
		ret = gnutls_record_recv (session, buffer, MAX_BUF);

		if (ret == 0) {
			printf ("\n- Peer has closed the GnuTLS connection\n");
			break;
		} else if (ret < 0 && gnutls_error_is_fatal (ret) == 0) {
			fprintf (stderr, "*** Warning: %s\n", gnutls_strerror (ret));
		} else if (ret < 0) {
			fprintf (stderr, "\n*** Received corrupted data(%d). Closing the connection.\n\n", ret);
			break;
		} else if (ret > 0) {
			// echo data back to the client
			gnutls_record_send (session, buffer, ret);
		}
	}
	printf ("\n");
	// do not wait for the peer to close the connection.
	gnutls_bye (session, GNUTLS_SHUT_WR);

	close (client_socket_descriptor);
	gnutls_deinit (session);
}

