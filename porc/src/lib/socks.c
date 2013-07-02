#include "socks.h"

/*
	new_client - Initialize a SOCKS connection. This function is called once during the SOCKSv4 handshake.

	client_socket_descriptor - SOCKS client socket descriptor
	ip - target ip
	port - target port

	This function returns 0 in case of success and -1 otherwise.
*/
int new_client(int client_socket_descriptor, uint32_t ip, uint16_t port) {
	printf("Creation of new socks client\n");
	int socks_session_id;
	ITEM_CLIENT *socks_session;

	// Register a new SOCKS session
	socks_session_id = ChainedListNew (&socks_session_list, (void **)&socks_session, sizeof(ITEM_CLIENT));
	socks_session->client_socket_descriptor = client_socket_descriptor;
	// SOCKS handshake

	PORC_COMMAND_OPEN_SOCKS_CONTENT porc_command_open_socks_content;
	porc_command_open_socks_content.ip = ip;
	porc_command_open_socks_content.port = port;
	porc_command_open_socks_content.socks_session_id = socks_session_id;
	printf("begin of socks handshake\n");
	if (client_porc_send (PORC_COMMAND_OPEN_SOCKS, (char *)&porc_command_open_socks_content,
		sizeof (porc_command_open_socks_content)) != 0)
	{
		fprintf (stderr, "Error PORC_COMMAND_OPEN_SOCKS (100)\n");
		ChainedListRemove (&socks_session_list, socks_session_id);
		close (client_socket_descriptor);
		return -1;	
	}
	printf("PORC_COMMAND_OPEN_SOCKS sent\n");
	//Now, leaves the work of finishing the Handshake to the other thread, because can't listen on the other socket 
	//(only one thread at a time)
	return 0;
}


int handle_connection(int client_socket_descriptor) {
	SOCKS4RequestHeader header;
	SOCKS4IP4RequestBody req;

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

	if (new_client (client_socket_descriptor, ntohl(req.ip_dst), ntohs(req.port)) == -1) {
		fprintf (stderr, "Failed to connect to target.\n");
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


