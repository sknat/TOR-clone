/*
	relay - PORC relay

	The PORC relay transfers a stream to another relay or to the target.
*/

#include "relaymain.h"

static gnutls_priority_t priority_cache;

pthread_t accepting_thread;
pthread_t selecting_thread;


CHAINED_LIST tls_session_list;
CHAINED_LIST porc_session_list;
CHAINED_LIST socks_session_list;


/*
	handle_connection - Sets up a TLS and a PORC session with a client or relay.
*/
int handle_connection(int client_socket_descriptor) {
	gnutls_session_t session;
	int ret;

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
	printf ("Tls handshake was completed\n");

	// TODO : Start a PORC session

	// Record the PORC session
	ITEM_PORC_SESSION *porc_session;
	int id_porc_session;
	id_porc_session = ChainedListNew (&porc_session_list, (void *)&porc_session, sizeof(ITEM_PORC_SESSION));
	// TODO: porc_session->...=...;


	// Signaling a new available socket to the selecting thread
	if (pthread_kill (selecting_thread, SIGUSR1) != 0) {
		fprintf (stderr, "Signal sending failed\n");
		return -1;
	}	

	return 0;
}



int accepting (int listen_socket_descriptor) {
	struct sockaddr_in sockaddr_client;
	int client_socket_descriptor;
	socklen_t length = sizeof(sockaddr_client);
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


void *start_accepting (void *arg) {
	return ((void *)accepting((int)arg));
}
	




int set_fds (int *nfds, fd_set *fds) {
	CHAINED_LIST_LINK *c;
	int max = -2;
	int n=1;

	FD_ZERO (fds);

	for (c=porc_session_list.first; c!=NULL; c=c->nxt) {
		FD_SET (((ITEM_PORC_SESSION*)(c->item))->socket_descriptor, fds);
		n++;
		if (((ITEM_PORC_SESSION*)(c->item))->socket_descriptor > max) {
			max = ((ITEM_PORC_SESSION*)(c->item))->socket_descriptor;
		}
	}

	for (c=socks_session_list.first; c!=NULL; c=c->nxt) {
		if (((ITEM_SOCKS_SESSION*)(c->item))->type == SOCKS_TO_TARGET) {
			FD_SET (((ITEM_SOCKS_SESSION*)(c->item))->target_socket_descriptor, fds);
			n++;
			if (((ITEM_SOCKS_SESSION*)(c->item))->target_socket_descriptor > max) {
				max = ((ITEM_SOCKS_SESSION*)(c->item))->target_socket_descriptor;
			}
		}
	}

	*nfds = max + 1;
	return n;	
}



int process_order(char *buffer, int n, int porc_session_id) {
	return 0;
}


int send_to_porc(char *buffer, int n, int socks_session_id) {
	return 0;
}

int selecting() {
	fd_set read_fds;
	int ret, nbr;
	int nfds;
	char buffer[BUF_SIZE+1];
	CHAINED_LIST_LINK *c;
	sigset_t signal_set_tmp, signal_set;

	sigemptyset(&signal_set_tmp);
	ret = pthread_sigmask (SIG_BLOCK, &signal_set_tmp, &signal_set);
	if (ret != 0) {
		fprintf (stderr, "Impossible to get the current signal mask.\n");
		return -1;
	}
	ret = sigdelset (&signal_set, SIGUSR1);
	if (ret != 0) {
		fprintf (stderr, "Impossible to prepare the signal mask.\n");
		return -1;
	}

	for (;;) {
		set_fds (&nfds, &read_fds);

		while((nbr = pselect(nfds, &read_fds, 0, 0, 0, &signal_set)) > 0) {
			for (c=porc_session_list.first; c!=NULL; c=c->nxt) {
				if (FD_ISSET (((ITEM_PORC_SESSION*)(c->item))->socket_descriptor, &read_fds)) {
					int recvd = recv(((ITEM_PORC_SESSION*)(c->item))->socket_descriptor, buffer, BUF_SIZE, 0);
					if(recvd <= 0) {
						fprintf (stderr, "Stop (100), %d\n", c->id);
						return -1;
					}
					buffer [recvd] = '\0';
					printf ("Receiving from client (%d bytes) : %s\n", recvd, buffer);
					if (process_order(buffer, recvd, c->id)!=0) {
						fprintf (stderr, "Stop (250), %d\n", c->id);
						return -1;
					}
				}
			}
			for (c=socks_session_list.first; c!=NULL; c=c->nxt) {
				if (((ITEM_SOCKS_SESSION*)(c->item))->type == SOCKS_TO_TARGET) {
					if (FD_ISSET (((ITEM_SOCKS_SESSION*)(c->item))->target_socket_descriptor, &read_fds)) {
						int recvd = recv(((ITEM_SOCKS_SESSION*)(c->item))->target_socket_descriptor,
							buffer, BUF_SIZE, 0);
						if(recvd <= 0) {
							fprintf (stderr, "Stop (120), %d\n", c->id);
							return -1;
						}
						buffer [recvd] = '\0';
						printf ("Receiving from target (%d bytes) : %s\n", recvd, buffer);
						if (send_to_porc(buffer, recvd, c->id)!=0) {
							fprintf (stderr, "Stop (270), %d\n", c->id);
							return -1;
						}
					}
				}
			}
		}
	}

	return 0;
}






/*
	main - Initializes a TLS server and starts a thread for every client.
*/
int main (int argc, char **argv)
{
	int listen_socket_descriptor;
	struct sockaddr_in sockaddr_server;
	int port;
	int ret;

	if (argc != 2) {
		printf ("Incorrect number of argument : you must define a port to listen to\n");
		return -1;
	}
	port = atoi (argv[1]);

	if ((ret=signal_init()) != 0) {
		fprintf (stderr, "Error in signals initialisation\n");
		return -1;
	}

	if ((ret=mytls_server_init (port, &xcred, &priority_cache, &listen_socket_descriptor, &sockaddr_server))!=0) {
		fprintf (stderr, "Error in mytls_client_global_init()\n");
		return -1;
	}

	ChainedListInit (&tls_session_list);
	ChainedListInit (&porc_session_list);
	ChainedListInit (&socks_session_list);

	selecting_thread = pthread_self ();

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	ret = pthread_create(&accepting_thread, &attr, start_accepting, (void *)listen_socket_descriptor);
	if (ret != 0) {
		fprintf (stderr, "Thread creation failed\n");
		gnutls_certificate_free_credentials (xcred);
		gnutls_priority_deinit (priority_cache);
		gnutls_global_deinit ();
		return -1;
	}

	selecting ();

	ChainedListClear (&tls_session_list);
	ChainedListClear (&porc_session_list);
	ChainedListClear (&socks_session_list);

	gnutls_certificate_free_credentials (xcred);
	gnutls_priority_deinit (priority_cache);
	gnutls_global_deinit ();

	return 0;
}


