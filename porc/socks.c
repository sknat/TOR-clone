#include "socks.h"

/*
	new_client - Initialize the PORC connection. This function is called once during the SOCKSv4 handshake.

	client_socket_descriptor - SOCKS client socket descriptor
	ip - target ip
	port - target port

	This function returns 0 in case of success and -1 otherwise.
*/
int new_client(int client_socket_descriptor, uint32_t ip, uint16_t port) {
	PORC_COMMAND porc_command;
	PORC_ACK porc_ack;
	MYSOCKET target;
	ITEM_CLIENT *socks_session;


	// PORC handshake
// envoyer en plus un numéro de session
	porc_command = PORC_COMMAND_OPEN_SOCKS;
	if (gnutls_record_send (client_circuit.session, (char *)&porc_command, sizeof (porc_command)) != sizeof (porc_command)) {
		fprintf (stderr, "Error PORC_COMMAND_OPEN_SOCKS (100)\n");
		close (client_socket_descriptor);
		return -1;	
	}

	target.ip = ip;
	target.port = port;
	if (gnutls_record_send (client_circuit.session, (char *)&target, sizeof (target))
		!= sizeof (target))
	{
		fprintf (stderr, "Error PORC_COMMAND_OPEN_SOCKS (200)\n");
		close (client_socket_descriptor);
		return -1;	
	}

	if (gnutls_record_recv (client_circuit.session, (char *)&porc_ack, sizeof (porc_ack))
		!= sizeof (porc_ack))
	{
		fprintf (stderr, "Error PORC_COMMAND_OPEN_SOCKS (250)\n");
		close (client_socket_descriptor);
		return -1;	
	}

	/*if (porc_ack != PORC_ACK_CONNECT_TARGET) {
		printf ("Impossible to join target\n");
		close (client_socket_descriptor);
		return 0;
	}*/


	// Record the PORC session

	ChainedListNew (&socks_session_list, (void*)&socks_session, sizeof(ITEM_CLIENT));
	socks_session->client_socket_descriptor = client_socket_descriptor;

	return 1;
}


int handle_connection(int client_socket_descriptor) {
	SOCKS4RequestHeader header;
	SOCKS4IP4RequestBody req;
	SOCKS4Response response;

	recv(client_socket_descriptor, (char*)&header, sizeof(SOCKS4RequestHeader), 0);
	if(header.version != 4 || header.cmd != CMD_CONNECT) {
		fprintf (stderr, "Incorrect header.\n");
		return -1;}
	if(recv(client_socket_descriptor, (char*)&req, sizeof(SOCKS4IP4RequestBody), 0) != sizeof(SOCKS4IP4RequestBody)) {
		fprintf (stderr, "Error in request reception.\n");
		return -1;}
	char c=' ';
	while(c!='\0') {
		if(recv(client_socket_descriptor, &c, 1, 0) != 1) {
			fprintf (stderr, "Error in username reception.\n");
			return -1;}
	}

	if (new_client (client_socket_descriptor, req.ip_dst, ntohs(req.port)) == -1) {
		fprintf (stderr, "Failed to connect to target.\n");
		return -1;
	}

	response.null_byte=0;
	response.status=RESP_SUCCEDED;
	response.rsv1=0;
	response.rsv2=0;

	if (send(client_socket_descriptor, (const char*)&response, sizeof(SOCKS4Response), 0)
		!= sizeof(SOCKS4Response)) 
	{
		fprintf (stderr, "Error in response\n");
		return -1;
	}

	// Signaling a new available socket to the selecting thread
	if (pthread_kill (selecting_thread, SIGUSR1) != 0) {
		fprintf (stderr, "Signal sending failed\n");
		return -1;
	}	

	return 0;
}

int proxy_socksv4 (int port) {
	struct sockaddr_in sockaddr_client;
	int listen_socket_descriptor;
	int client_socket_descriptor;
	socklen_t length = sizeof(sockaddr_client);

	listen_socket_descriptor = create_listen_socket(port);
	if(listen_socket_descriptor == -1) {
		fprintf (stderr, "Failed to create server\n");
		return -1;
	}
	printf ("Listening\n");

	for (;;) {
		if ((client_socket_descriptor = accept(listen_socket_descriptor, (struct sockaddr *) 
			&sockaddr_client, &length)) > 0) 
		{
			printf ("New client %d\n", client_socket_descriptor);
			if (handle_connection (client_socket_descriptor) != 0) 
			{
				break;
			}
		}
	}

	return 0;
}


