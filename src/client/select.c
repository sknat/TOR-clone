/* ################################################################################

						Porc client selecting Thread

   ################################################################################*/

#include "select.h"

////////////////////////////////////////////////////////////////////////////////////////
//		Send a packet to the first known relay of the tunnel
//		Just give in a text buffer to send, its length and the session_id
////////////////////////////////////////////////////////////////////////////////////////
int send_to_relay(char *buffer, int buffer_len, int item_client_id) 
	{
	//Generate appropriate header
	PORC_CONTENT_TRANSMIT * payload_header = malloc(sizeof(PORC_CONTENT_TRANSMIT));
	payload_header->socks_session_id = item_client_id;
	char * out_buffer = malloc(sizeof(PORC_CONTENT_TRANSMIT)+buffer_len);
	memcpy(out_buffer,payload_header,sizeof(PORC_CONTENT_TRANSMIT));
	memcpy(out_buffer+sizeof(PORC_CONTENT_TRANSMIT),buffer,buffer_len);	
	//Send it
	if (client_porc_send (PORC_COMMAND_TRANSMIT, out_buffer, sizeof(PORC_CONTENT_TRANSMIT)+buffer_len)!=0)
	{
		fprintf(stderr,"Error sending buffer to the first Porc relay (client)\n");
		return -1;
	}
	free(payload_header);
	return 0;
}


int set_fds (int *nfds, fd_set *fds) {
	CHAINED_LIST_LINK *c;
	int max = client_circuit.relay1_socket_descriptor;
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
	printf ("set_fds returns %i\n", n);

	*nfds = max + 1;
	return n;	
}

int client_process_porc_packet()
{
	PORC_RESPONSE porc_response;
	char * payload;
	size_t payload_length;
	if (client_porc_recv (&porc_response, &payload, &payload_length)!=0)
	{
		fprintf (stderr, "Stop (40)\n");
		return -1;
	}
	if (porc_response == PORC_RESPONSE_OPEN_SOCKS)
	{
		printf ("Received PORC_RESPONSE_OPEN_SOCKS\n");
		PORC_RESPONSE_OPEN_SOCKS_CONTENT *porc_response_open_socks_content
			= (PORC_RESPONSE_OPEN_SOCKS_CONTENT*) payload; 
		ITEM_CLIENT * client;
		if (ChainedListFind (&socks_session_list, porc_response_open_socks_content->socks_session_id, (void**) &client)!=0)
		{
			fprintf (stderr,"Socks session id not found\n");
			return 0;
		}
		printf("client socket descr : %i\n",client->client_socket_descriptor);

		SOCKS4Response socks_response;
		socks_response.null_byte=0;
		socks_response.rsv1=0;
		socks_response.rsv2=0;

		if (porc_response_open_socks_content->status != PORC_STATUS_SUCCESS) 
		{
			printf ("Impossible to join target\n");
			socks_response.status=RESP_ERROR;
			ChainedListRemove (&socks_session_list, porc_response_open_socks_content->socks_session_id);
			return 0;
		} else {
			printf("Target joined\n");
			socks_response.status=RESP_SUCCEDED;
			ChainedListComplete(&socks_session_list, porc_response_open_socks_content->socks_session_id);
		}

		if (send(client->client_socket_descriptor, (const char*)&socks_response, sizeof(SOCKS4Response), 0)
			!= sizeof(SOCKS4Response)) 
		{
			fprintf (stderr, "Error in socks_response\n");
			return -1;
		}

		printf("SIGUSR1\n");
		// Signaling a new available socket to the selecting thread
		if (pthread_kill (selecting_thread, SIGUSR1) != 0) {
			fprintf (stderr, "Signal sending failed\n");
			return -1;
		}	
		printf("SIGUSR1 done\n");
	}
	else if (porc_response == PORC_RESPONSE_TRANSMIT)
	{
		printf ("Received PORC_RESPONSE_TRANSMIT\n");
		ITEM_CLIENT * client;
		PORC_CONTENT_RETURN * porc_content_return = (PORC_CONTENT_RETURN*) payload;
		if (ChainedListFind (&socks_session_list, porc_content_return->socks_session_id, (void**) &client)!=0)
		{
			fprintf (stderr,"Socks session id not found\n");
			return 0;
		}
		printf ("Receiving from relay (%d bytes) : %s\n", payload_length, payload);
		size_t message_length = payload_length - sizeof(PORC_CONTENT_RETURN);
		char * message = payload+sizeof(PORC_CONTENT_RETURN);
		if (send(client->client_socket_descriptor, message, message_length, 0)
			!= message_length) 
		{
			fprintf (stderr, "Error in socks_response (100)\n");
			return -1;
		}
	}
	else if (porc_response == PORC_RESPONSE_CLOSE_SOCKS)
	{
		printf ("Received PORC_RESPONSE_CLOSE_SOCKS\n");
		ITEM_CLIENT * client;
		PORC_RESPONSE_CLOSE_SOCKS_CONTENT * porc_response_socks_content = (PORC_RESPONSE_CLOSE_SOCKS_CONTENT*) payload;
		if (ChainedListFind (&socks_session_list, porc_response_socks_content->socks_session_id, (void**) &client)!=0)
		{
			fprintf (stderr,"Socks session id not found\n");
			return 0;
		}
		printf ("SOCKS connection is closed by target\n");
		close (client->client_socket_descriptor);
		ChainedListRemove (&socks_session_list, porc_response_socks_content->socks_session_id);
	}
	free(payload);
	return 0;
}

int client_process_socks_packet(int client_id)
{
	char buffer[SOCKS_BUFFER_SIZE+1];
	ITEM_CLIENT * client;
	if (ChainedListFind (&socks_session_list, client_id, (void **)&client)!=0)
	{
		fprintf (stderr, "Stop (80)\n");
		return -1;
	}

	printf("Received a message from a SOCKS client\n");
	int recvd = recv(client->client_socket_descriptor, buffer, SOCKS_BUFFER_SIZE, 0);
	if(recvd < 0) 
	{
		fprintf (stderr, "Stop (100), %d\n", client_id);
		return -1;
	}
	if(recvd == 0) 
	{
		printf ("SOCKS Client stoped connection, %d\n", client_id);
		ChainedListRemove (&socks_session_list, client_id);
		return 0;
	}
	buffer [recvd] = '\0';
	printf ("Receiving from client (%d bytes) : %s\n", recvd, buffer);
	if (send_to_relay(buffer, recvd, client_id)!=0) 
	{
		fprintf (stderr, "Stop (250), %d\n", client_id);
		return -1;
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////
//		do_proxy - Process existing PORC client connections.
//
// 	Do proxy between a clear connections and a secure connection.
////////////////////////////////////////////////////////////////////////
int do_proxy() {
	printf("starting socks proxy...\n");
	fd_set read_fds;
	int ret, nbr;
	int nfds;
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

	printf("Entering thread loop\n");
	for (;;) {
		printf ("About to set fds\n");
		if (set_fds (&nfds, &read_fds) == -1) {
			fprintf (stderr, "Preventing a dead-lock.\n");
			return -1;
		}
		printf ("fds set\n");

		if((nbr = pselect(nfds, &read_fds, 0, 0, 0, &signal_set)) > 0) {
			printf("pselect returned %i\n",nbr);
			if (FD_ISSET (client_circuit.relay1_socket_descriptor, &read_fds)) 
			{
				printf("Received a message from PORC network\n");
				client_process_porc_packet();
			}
			for (c=socks_session_list.first; c!=NULL; c=c->nxt) 
			{
				if (FD_ISSET (((ITEM_CLIENT*)(c->item))->client_socket_descriptor, &read_fds)) 
				{
					client_process_socks_packet(c->id);
				}
			}
		}
		if (nbr == 0) {
			printf ("nbr = 0 (timeout?)\n");;
			return -1;
		} else if (nbr == -1) {
			if (errno == EINTR) {
				printf ("pselect() was interrupted\n");
			} else {
				printf ("pselect() returned with error %d\n", errno);
				return -1;
			}
		}
	}

	return 0;
}

