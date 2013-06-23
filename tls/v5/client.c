/*
	client - PORC client

	The PORC client acts is a SOCKSv4 proxy between client seeking for a secure and anonymous connexion and a PORC relay.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"
#include "mytls.h"
#include "socks.h"

/*
	CLIENT_STREAM - Stream information for the PORC client.
*/
typedef struct CLIENT_STREAM {
	int client_socket_descriptor;
}	CLIENT_STREAM;
#define MAX_CLIENT_STREAMS	1000;
CLIENT_STREAM client_stream[MAX_CLIENT_STREAMS];
void client_stream_init ();			// initialisation of client_stream
int client_stream_find_socket (int id);		// find the socket descriptor of a stream, -1 if no such stream exist
int client_stream_find_id (int client_socket_descriptor);	// find the id of a stream, -1 if no such stream exist
int client_stream_new (int client_socket_descriptor);		// define a free stream, -1 if no free stream
void client_stream_free (int index);		// free a stream


/*
	CLIENT_CIRCUIT - Circuit information for the PORC client.
*/
typedef struct CLIENT_CIRCUIT {
	MYSOCKET relay1;
	gnutls_session_t session;
	int relay1_socket_descriptor;
	MYSOCKET relay2;
	MYSOCKET relay3;
}	CLIENT_CIRCUIT;
CLIENT_CIRCUIT	client_circuit;
int client_circuit_init ();
void client_circuit_free ();


int nbr_relays = 0;
MYSOCKET *list_relays = NULL;


void set_fds (int *nfds, fd_set &fds) {
	int i;
	int max = -2;
	int n;

	n=0;
	FD_ZERO (&fds);
	for (i=0; i<MAX_CLIENT_STREAMS; i++) {
		if (client_stream[i] != -1) {
			FD_SET (client_stream[i], &fds);
			n++;
			if (client_stream[i]>max) {
				max = client_stream[i];
			}
		}			
	}

	*ndfs = max + 1;
	return n;	
}


/*
	do_proxy - Process existing PORC client connections.

	Do proxy between a clear connections and a secure connection.
*/
void do_proxy() {
	fd_set read_fds;
	int result;
	int nfds;
	char buffer[BUF_SIZE+1];

	for (;;) {
		while (set_fds (&nfds, &read_fds) == 0) {
			sleep (1);
		}

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

			while (set_fds (&nfds, &read_fds) == 0) {
				sleep (1);
			}
		}
	}
}


/*
	new_stream - new_client function for the PORC client.

	Creates and returns a pointer to a new PORC_STREAM structure for the new client.
*/
void *new_stream(int client_socket_descriptor, uint32_t ip, uint16_t port) {
	int socket_descriptor;
	int ret;
	gnutls_session_t session;
	PORC_COMMAND porc_command;
	PORC_ACK porc_ack;
	MYSOCKET target;

	porc_command = PORC_COMMAND_CONNECT_TARGET;
	target.ip = ip;
	target.port = port;

	int stream_id = client_stream_new (client_socket_descriptor);
	if (stream_id == -1) {
		fprintf (stderr, "Too much connection\n");
		return -1;
	}

	if (gnutls_record_send (client_circuit.session, (char *)&porc_command, sizeof (porc_command)) != sizeof (porc_command)) {
		fprintf (stderr, "Error PORC_COMMAND_CONNECT_TARGET (100)\n");
		client_stream_free (stream_id);
		close (client_circuit.socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	if (gnutls_record_send (client_circuit.session, (char *)&target, sizeof (target))
		!= sizeof (target))
	{
		fprintf (stderr, "Error PORC_COMMAND_CONNECT_TARGET (200)\n");
		client_stream_free (stream_id);
		close (client_circuit.socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	if (gnutls_record_recv (session, (char *)&porc_ack, sizeof (porc_ack))
		!= sizeof (porc_ack))
	{
		fprintf (stderr, "Error PORC_COMMAND_CONNECT_TARGET (250)\n");
		client_stream_free (stream_id);
		close (client_circuit.socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	if (porc_ack != PORC_ACK_CONNECT_TARGET) {
		client_stream_free (stream_id);
		fprintf (stderr, "Impossible to join target (300)\n");
		return -1;
	}

	return (void *)1;
}


void start_proxy(void *arg){
	proxy_socksv4 ((int)arg);
}

int main () {
	int ret;

	if ((ret=mytls_client_global_init (&xcred))<0) {
		fprintf (stderr, "Error in mytls_client_global_init()\n");
		return -1;
	}

	client_stream_init ();

	if (client_circuit_init () != 0) {
		fprintf (stderr, "Error in circuit initialisation\n");
		gnutls_certificate_free_credentials (xcred);
		gnutls_global_deinit ();
		return -1;
	}

	new_client = *new_stream;

	pthread_t thread;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&thread, &attr, start_proxy, (void*)CLIENT_PORT);

	do_proxy ();

	client_circuit_free ();

	gnutls_certificate_free_credentials (xcred);
	gnutls_global_deinit ();

	return 0;
}





void client_stream_init () {
	int i;
	for (i=0; i<MAX_CLIENT_STREAMS; i++) {
		client_steam[i].client_socket_descriptor = -1;
	}
}

int client_stream_find_socket (int id) {
	return client_steam[id];
}

int client_stream_find_id (int client_socket_descriptor) {
	int i;
	for (i=0; i<MAX_CLIENT_STREAMS; i++) {
		if (client_steam[i].client_socket_descriptor == client_socket_descriptor) {
			return i;
		}
	}
	return -1;
}

int client_stream_new (int client_socket_descriptor) {
	int i;
	for (i=0; i<MAX_CLIENT_STREAMS; i++) {
		if (client_steam[i].client_socket_descriptor == -1) {
			client_steam[i].client_socket_descriptor = client_socket_descriptor;
			return i;
		}
	}
	return -1;
}

void client_stream_free (int index) {
	client_steam[id] = -1;
}





int client_circuit_init () {
	int socket_descriptor;
	int ret;
	gnutls_session_t session;
	DIRECTORY_REQUEST directory_request;
	DIRECTORY_RESPONSE directory_response;

	// Ask for the relay list to the PORC directory

	ret = mytls_client_session_init (inet_addr(DIRECTORY_IP), htons(DIRECTORY_PORT), &session, &socket_descriptor);
	if (ret < 0) {
		fprintf (stderr, "Error joining directory\n");
		return -1;
	}

	directory_request.command = DIRECTORY_ASK;

	if (gnutls_record_send (session, (char *)&directory_request, sizeof (directory_request)) != sizeof (directory_request)) {
		fprintf (stderr, "directory request error (100)\n");
		close (socket_descriptor);
		gnutls_deinit (session);
		return -1;	
	}

	if (gnutls_record_recv (session, (char *)&directory_response, sizeof (directory_response))
		!= sizeof (directory_response))
	{
		fprintf (stderr, "directory request error (200)\n");
		close (socket_descriptor);
		gnutls_deinit (session);
		return NULL;	
	}

	if (porc_handshake_response.status != DIRECTORY_SUCCESS) {
		fprintf (stderr, "directory request error (300)\n");
		close (socket_descriptor);
		gnutls_deinit (session);
		return NULL;	
	}

	if (nbr_relays != 0) {
		free (list_relays);
	}
	nbr_relays = porc_handshake_response.nbr;
	list_relays = (void *)malloc(sizeof(MYSOCKET)*nbr_relays);

	if (gnutls_record_recv (session, (char *)list_relays, sizeof(MYSOCKET)*nbr_relays)
		!= sizeof(MYSOCKET)*nbr_relays)
	{
		fprintf (stderr, "directory request error (400)\n");
		close (socket_descriptor);
		gnutls_deinit (session);
		return NULL;	
	}

	printf ("Received %d trusted relays.\n", nbr_relays);

	close (socket_descriptor);
	gnutls_deinit (session);

	
	// Join the 1st relay
	PORC_COMMAND porc_command;
	PORC_ACK porc_ack;

	srand(time(NULL));
	int r = rand() % nbr_relays;		// Select a random relay
	client_circuit.relay1.ip = list_relays[r].ip;
	client_circuit.relay1.port = list_relays[r].port;

	ret = mytls_client_session_init (client_circuit.relay1.ip, client_circuit.relay1.port
		 &(client_circuit.session), (&client_circuit.socket_descriptor));
	if (ret < 0) {
		fprintf (stderr, "Error joining 1st relay\n");
		return -1;
	}

	porc_command = PORC_COMMAND_CONNECT_RELAY;

	if (gnutls_record_send (client_circuit.session, (char *)&porc_command, sizeof (porc_command)) != sizeof (porc_command)) {
		fprintf (stderr, "Error PORC_COMMAND_CONNECT_RELAY (100)\n");
		close (client_circuit.socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	r = rand() % nbr_relays;		// Select a 2nd random relay
	client_circuit.relay2.ip = list_relays[r].ip;
	client_circuit.relay2.port = list_relays[r].port;

	if (gnutls_record_send (client_circuit.session, (char *)&client_circuit.relay2, sizeof (client_circuit.relay2))
		!= sizeof (client_circuit.relay2))
	{
		fprintf (stderr, "Error PORC_COMMAND_CONNECT_RELAY (200)\n");
		close (client_circuit.socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	if (gnutls_record_recv (session, (char *)&porc_ack, sizeof (porc_ack))
		!= sizeof (porc_ack))
	{
		fprintf (stderr, "Error PORC_COMMAND_CONNECT_RELAY (250)\n");
		close (client_circuit.socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	if (porc_ack != PORC_ACK_CONNECT_RELAY) {
		fprintf (stderr, "Error PORC_COMMAND_CONNECT_RELAY (300)\n");
		close (client_circuit.socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	r = rand() % nbr_relays;		// Select a 3rd random relay
	client_circuit.relay3.ip = list_relays[r].ip;
	client_circuit.relay3.port = list_relays[r].port;

	if (gnutls_record_send (client_circuit.session, (char *)&client_circuit.relay3, sizeof (client_circuit.relay3))
		!= sizeof (client_circuit.relay3))
	{
		fprintf (stderr, "Error PORC_COMMAND_CONNECT_RELAY (1200)\n");
		close (client_circuit.socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	if (gnutls_record_recv (session, (char *)&porc_ack, sizeof (porc_ack))
		!= sizeof (porc_ack))
	{
		fprintf (stderr, "Error PORC_COMMAND_CONNECT_RELAY (1250)\n");
		close (client_circuit.socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	if (porc_ack != PORC_ACK_CONNECT_RELAY) {
		fprintf (stderr, "Error PORC_COMMAND_CONNECT_RELAY (1300)\n");
		close (client_circuit.socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	printf ("PORC circuit set up\n");

	porc_stream = malloc (sizeof(PORC_STREAM));
	porc_stream->ip = ip;
	porc_stream->port = port;
	porc_stream->session = session;
	porc_stream->socket_descriptor = socket_descriptor;

	return 0
}

void client_circuit_free () {
	PORC_COMMAND porc_command = PORC_COMMAND_DISCONNECT;

	if (gnutls_record_send (client_circuit.session, (char *)&porc_command, sizeof (porc_command)) != sizeof (porc_command)) {
		fprintf (stderr, "Error PORC_COMMAND_DISCONNECT (100)\n");
		close (client_circuit.socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	if (gnutls_record_send (client_circuit.session, (char *)&porc_command, sizeof (porc_command)) != sizeof (porc_command)) {
		fprintf (stderr, "Error PORC_COMMAND_DISCONNECT (200)\n");
		close (client_circuit.socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	if (gnutls_record_send (client_circuit.session, (char *)&porc_command, sizeof (porc_command)) != sizeof (porc_command)) {
		fprintf (stderr, "Error PORC_COMMAND_DISCONNECT (300)\n");
		close (client_circuit.socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	close (client_circuit.socket_descriptor);
	gnutls_deinit (client_circuit.session);
}

