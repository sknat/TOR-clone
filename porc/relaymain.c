/*
	relay - PORC relay

	The PORC relay transfers a stream to another relay or to the target.
*/

#include "relaymain.h"

static gnutls_priority_t priority_cache;

pthread_t accepting_thread;
pthread_t selecting_thread;


/*
	main - Initializes a TLS server and starts a thread for every client.
*/
int main (int argc, char **argv)
{
	int listen_socket_descriptor;
	struct sockaddr_in sockaddr_client;
	socklen_t client_adress_length;
	char topbuf[512];
	int port;
	int ret;

	if (argc != 2) {
		printf ("Incorrect number of argument : you must define a port to listen to\n");
		return -1;
	}
	port = atoi (argv[1]);

	if ((ret=signal_init) != 0) {
		fprintf (stderr, "Error in signals initialisation\n");
		return -1;
	}

	if ((ret=mytls_server_init (port, &xcred, &priority_cache, &listen_socket_descriptor, &sockaddr_server))!=0) {
		fprintf (stderr, "Error in mytls_client_global_init()\n");
		return -1;
	}

	// Set up the connection to the PORC network
	if (client_circuit_init () != 0) {
		fprintf (stderr, "Error in circuit initialisation\n");
		gnutls_certificate_free_credentials (xcred);
		gnutls_global_deinit ();
		return -1;
	}

	RelayChainedListInit (&porc_sessions);

	selecting_thread = pthread_self ();

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	ret = pthread_create(&accepting_thread, &attr, start_accepting, (void *)listen_socket_descriptor);
	if (ret != 0) {
		fprintf (stderr, "Thread creation failed\n");
		client_circuit_free ();
		gnutls_certificate_free_credentials (xcred);
		gnutls_priority_deinit (priority_cache);
		gnutls_global_deinit ();
		return -1;
	}

	start_selecting ();

	client_circuit_free ();
	gnutls_certificate_free_credentials (xcred_serv);
	gnutls_priority_deinit (priority_cache);
	gnutls_global_deinit ();

	return 0;
}


void *start_accepting (void *arg) {
	return ((void *)accepting((int)arg));
}
	


int accepting (int listen_socket_descriptor) {
	struct sockaddr_in sockaddr_client;
	int client_socket_descriptor;
	unsigned int length = sizeof(sockaddr_client);
	int ret;

	for (;;) {
		if ((client_socket_descriptor = accept(listen_socket_descriptor, (struct sockaddr *) &sockaddr_client, &length)) > 0) {
			printf ("New client %d\n", client_socket_descriptor);
			ret = handle_connection (client_socket_descriptor);
			if (ret != 0) {
				break;
			}
		}
	}

	return ret;
}


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
	handle_connection - Sets up a PORC session.
*/
int handle_connection(int client_socket_descriptor) {
	gnutls_session_t session;
	int ret;
	RELAY_CHAINED_LIST_ITEM *porc_session;

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
		fprintf (stderr, "*** Handshake has failed (%s)\n\n", gnutls_strerror (ret));
		return -1;
	}
	printf ("- Handshake was completed\n");

	// Record the PORC session

	RelayChainedListNew (&porc_sessions, &porc_session);

	porc_session.socket_descriptor = client_socket_descriptor;
	porc_session.session = session;
	porc_session.type = SOCKET_INRELAY;


	porc_session->client_socket_descriptor = client_socket_descriptor;
	porc_session->ip = ip;
	porc_session->port = port;

	return 0;
}




