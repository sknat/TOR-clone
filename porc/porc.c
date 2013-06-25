#include "porc.h"

int nbr_relays = 0;
MYSOCKET *list_relays = NULL;

int client_circuit_init () {
	int socket_descriptor;
	gnutls_session_t session;
	DIRECTORY_REQUEST directory_request;
	DIRECTORY_RESPONSE directory_response;

	// Ask for the relay list to the PORC directory
	if (mytls_client_session_init (inet_addr(DIRECTORY_IP), htons(DIRECTORY_PORT), &session, &socket_descriptor) < 0) {
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
		return -1;
	}

	if (directory_response.status != DIRECTORY_SUCCESS) {
		fprintf (stderr, "directory request error (300)\n");
		close (socket_descriptor);
		gnutls_deinit (session);
		return -1;	
	}

	if (nbr_relays != 0) {
		free (list_relays);
	}
	
	nbr_relays = directory_response.nbr;
	list_relays = (void *)malloc(sizeof(MYSOCKET)*nbr_relays);

	if (gnutls_record_recv (session, (char *)list_relays, sizeof(MYSOCKET)*nbr_relays)
		!= sizeof(MYSOCKET)*nbr_relays)
	{
		fprintf (stderr, "directory request error (400)\n");
		close (socket_descriptor);
		gnutls_deinit (session);
		return -1;	
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

	if (mytls_client_session_init (client_circuit.relay1.ip, client_circuit.relay1.port,
		 &(client_circuit.session), (&client_circuit.relay1_socket_descriptor)) < 0) 
	{
		fprintf (stderr, "Error joining 1st relay\n");
		return -1;
	}

	porc_command = PORC_COMMAND_CONNECT_RELAY;

	if (gnutls_record_send (client_circuit.session, (char *)&porc_command, sizeof (porc_command)) != sizeof (porc_command)) {
		fprintf (stderr, "Error PORC_COMMAND_CONNECT_RELAY (100)\n");
		close (client_circuit.relay1_socket_descriptor);
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
		close (client_circuit.relay1_socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	if (gnutls_record_recv (session, (char *)&porc_ack, sizeof (porc_ack))
		!= sizeof (porc_ack))
	{
		fprintf (stderr, "Error PORC_COMMAND_CONNECT_RELAY (250)\n");
		close (client_circuit.relay1_socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	if (porc_ack != PORC_ACK_CONNECT_RELAY) {
		fprintf (stderr, "Error PORC_COMMAND_CONNECT_RELAY (300)\n");
		close (client_circuit.relay1_socket_descriptor);
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
		close (client_circuit.relay1_socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}
	
	if (gnutls_record_recv (session, (char *)&porc_ack, sizeof (porc_ack))
		!= sizeof (porc_ack))
	{
		fprintf (stderr, "Error PORC_COMMAND_CONNECT_RELAY (1250)\n");
		close (client_circuit.relay1_socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	if (porc_ack != PORC_ACK_CONNECT_RELAY) {
		fprintf (stderr, "Error PORC_COMMAND_CONNECT_RELAY (1300)\n");
		close (client_circuit.relay1_socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	printf ("PORC circuit set up\n");

	return 0;
}

int client_circuit_free () {
	PORC_COMMAND porc_command = PORC_COMMAND_DISCONNECT;

	if (gnutls_record_send (client_circuit.session, (char *)&porc_command, sizeof (porc_command)) != sizeof (porc_command)) {
		fprintf (stderr, "Error PORC_COMMAND_DISCONNECT (100)\n");
		close (client_circuit.relay1_socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	if (gnutls_record_send (client_circuit.session, (char *)&porc_command, sizeof (porc_command)) != sizeof (porc_command)) {
		fprintf (stderr, "Error PORC_COMMAND_DISCONNECT (200)\n");
		close (client_circuit.relay1_socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	if (gnutls_record_send (client_circuit.session, (char *)&porc_command, sizeof (porc_command)) != sizeof (porc_command)) {
		fprintf (stderr, "Error PORC_COMMAND_DISCONNECT (300)\n");
		close (client_circuit.relay1_socket_descriptor);
		gnutls_deinit (client_circuit.session);
		return -1;	
	}

	close (client_circuit.relay1_socket_descriptor);
	gnutls_deinit (client_circuit.session);

	return 0;
}


