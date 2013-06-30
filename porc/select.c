#include "select.h"

////////////////////////////////////////////////////////////////////////////////////////
//		Send a packet to the first known relay of the tunnel
//		Just give in a text buffer to send, its length and the session_id
////////////////////////////////////////////////////////////////////////////////////////
int send_to_relay(char *buffer, int buffer_len, int porc_session_id) {
	
	
	
	return 0;
}


int set_fds (int *nfds, fd_set *fds) {
	CHAINED_LIST_LINK *c;
	int max = -2;
	int n = 1;

	FD_ZERO (fds);
	FD_SET (client_circuit.relay1_socket_descriptor, fds);
	for (c=socks_session_list.first; c!=NULL; c=c->nxt) {
		FD_SET (((ITEM_CLIENT*)(c->item))->client_socket_descriptor, fds);
		n++;
		if (((ITEM_CLIENT*)(c->item))->client_socket_descriptor>max) {
			max = ((ITEM_CLIENT*)(c->item))->client_socket_descriptor;
		}
	}

	*nfds = max + 1;
	return n;	
}


/*
	do_proxy - Process existing PORC client connections.

	Do proxy between a clear connections and a secure connection.
*/
int do_proxy() {
	fd_set read_fds;
	int ret, nbr;
	int nfds;
	char buffer[SOCKS_BUFFER_SIZE+1];
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
		if (set_fds (&nfds, &read_fds) == -1) {
			fprintf (stderr, "Preventing a dead-lock.\n");
			return -1;
		}

		while((nbr = pselect(nfds, &read_fds, 0, 0, 0, &signal_set)) > 0) {
			if (FD_ISSET (client_circuit.relay1_socket_descriptor, &read_fds)) {
				int recvd = gnutls_record_recv(client_circuit.relay1_gnutls_session, buffer, SOCKS_BUFFER_SIZE);
				if(recvd <= 0) {
					fprintf (stderr, "Stop (50) on relay reception\n");
					return -1;
				}
				buffer [recvd] = '\0';
				printf ("Receiving from relay (%d bytes) : %s\n", recvd, buffer);
				if (send_to_relay(buffer, recvd, c->id)!=0) {
					fprintf (stderr, "Stop (70), %d\n", c->id);
					return -1;
				}
			}
			for (c=socks_session_list.first; c!=NULL; c=c->nxt) {
				if (FD_ISSET (((ITEM_CLIENT*)(c->item))->client_socket_descriptor, &read_fds)) {
					int recvd = recv(((ITEM_CLIENT*)(c->item))->client_socket_descriptor, buffer, SOCKS_BUFFER_SIZE, 0);
					if(recvd <= 0) {
						fprintf (stderr, "Stop (100), %d\n", c->id);
						return -1;
					}
					buffer [recvd] = '\0';
					printf ("Receiving from client (%d bytes) : %s\n", recvd, buffer);
					if (send_to_relay(buffer, recvd, c->id)!=0) {
						fprintf (stderr, "Stop (250), %d\n", c->id);
						return -1;
					}
				}
			}
		}
	}

	return 0;
}


