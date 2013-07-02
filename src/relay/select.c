/* ################################################################################
							
							Relay - PORC relay

				Methods for porcessing established connections

   ################################################################################*/

#include "select.h"

int set_fds (int *nfds, fd_set *fds) {
	CHAINED_LIST_LINK *c;
	int max = -2;
	int n=0;
	
	FD_ZERO (fds); //Initialize set
	
	for (c=tls_session_list.first; c!= NULL; c=c->nxt) {
		if (c->complete == 1) {
			FD_SET (((ITEM_TLS_SESSION*)(c->item))->socket_descriptor, fds);
			n++;
			if (((ITEM_TLS_SESSION*)(c->item))->socket_descriptor > max) {
				max = ((ITEM_TLS_SESSION*)(c->item))->socket_descriptor;
			}
		}
	}

	for (c=socks_session_list.first; c!=NULL; c=c->nxt) {
		if (c->complete == 1) {
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


//////////////////////////////////////////////////////////////////////////
// Send a packet into the Porc tunnel adding correct header information
//////////////////////////////////////////////////////////////////////////
int relay_porc_send (int code, int porc_session_id, char *payload, size_t payload_length)
{
	int crypted_payload_length = ((sizeof(PORC_PAYLOAD_HEADER)+payload_length+CRYPTO_CIPHER_BLOCK_LENGTH-1)/
		CRYPTO_CIPHER_BLOCK_LENGTH)*CRYPTO_CIPHER_BLOCK_LENGTH;
	int porc_packet_length = sizeof(PORC_PACKET_HEADER) + crypted_payload_length;
	char *porc_packet = malloc(porc_packet_length);

	PORC_PACKET_HEADER *porc_packet_header = (PORC_PACKET_HEADER *)porc_packet;
	char *payload_in_packet = porc_packet + sizeof(PORC_PACKET_HEADER);
	PORC_PAYLOAD_HEADER *payload_header = (PORC_PAYLOAD_HEADER *)payload_in_packet;

	// find the porc session
	ITEM_PORC_SESSION *porc_session;
	if (ChainedListFind (&porc_session_list, porc_session_id, (void **)&porc_session) != 0) {
		fprintf (stderr, "Impossible to find the porc session\n");
		return -1;
	}

	porc_packet_header->length = porc_packet_length;
	porc_packet_header->direction = PORC_DIRECTION_UP;
	porc_packet_header->porc_session_id = porc_session->id_prev;
	payload_header->code = code;
	payload_header->length = sizeof(PORC_PAYLOAD_HEADER)+payload_length;
	memcpy(payload_in_packet+sizeof(PORC_PAYLOAD_HEADER), payload, payload_length);
	memset (payload_in_packet+sizeof(PORC_PAYLOAD_HEADER)+payload_length, 'a',
		crypted_payload_length-(sizeof(PORC_PAYLOAD_HEADER)+payload_length));

	// find the tls session
	ITEM_TLS_SESSION *tls_session;
	if (ChainedListFind (&tls_session_list, porc_session->client_tls_session, (void **)&tls_session) != 0) {
		fprintf (stderr, "Impossible to find the tls session\n");
		return -1;
	}

	if (gcry_cipher_encrypt (porc_session->gcry_cipher_hd, payload_in_packet, crypted_payload_length, NULL, 0)) {
		fprintf (stderr, "gcry_cipher_encrypt failed\n");
		return -1;
	}

	if (gnutls_record_send (tls_session->gnutls_session, porc_packet, porc_packet_length) != porc_packet_length)
	{
		fprintf (stderr, "Incorrect expected size to be sent in crelay_porc_send()\n");
		return -1;
	}

	free (porc_packet);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////
// Processes the packet incoming to porc
////////////////////////////////////////////////////////////////////////////////////////

int process_porc_packet(int tls_session_id) {
	ITEM_TLS_SESSION *tls_session;
	gnutls_session_t gnutls_session;
	
	ChainedListFind (&tls_session_list, tls_session_id, (void**)&tls_session);
	gnutls_session = tls_session->gnutls_session;

	printf ("A packet to process for the PORC network...\n");
	printf ("tls_session : %d, gnutls_session : %d\n", (int)tls_session, (int)gnutls_session);

	// Read the header : length, direction, porc_session_id
	PORC_PACKET_HEADER porc_packet_header;
	if (gnutls_record_recv (gnutls_session, (char *)&porc_packet_header, sizeof(porc_packet_header))
		!= sizeof (porc_packet_header))
	{
		fprintf (stderr, "Impossible to read the header of the PORC packet\n");
		return -1;
	}

	printf ("(length, direction, porc_session_id) : (%d, %d, %d)\n", porc_packet_header.length, porc_packet_header.direction,
		porc_packet_header.porc_session_id);

	if (porc_packet_header.length > PORC_MAX_PACKET_LENGTH) {
		fprintf (stderr, "Packet too long\n");
		return -1;
	}
	if (porc_packet_header.length <= sizeof(porc_packet_header)) {
		fprintf (stderr, "Packet too short\n");
		return -1;
	}

	int payload_length = porc_packet_header.length-sizeof(PORC_PACKET_HEADER);
	if (payload_length % CRYPTO_CIPHER_BLOCK_LENGTH != 0) {
		fprintf (stderr, "Incorrect payload length\n");
		return -1;
	}

	// Read the payload of the packet
	char *payload = malloc (payload_length);
	if (gnutls_record_recv (gnutls_session, payload, payload_length)
		!= payload_length)
	{
		fprintf (stderr, "Impossible to read the PORC packet payload\n");
		return -1;
	}

	int porc_session_id;
	ITEM_PORC_SESSION *porc_session;
	
	if (porc_packet_header.direction == PORC_DIRECTION_DOWN) {
		// We must decode
		printf ("direction is DOWN\n");

		CHAINED_LIST_LINK *c;
		porc_session_id = -1;
		for (c=porc_session_list.first; c!=NULL; c=c->nxt) {
			//If we know it as a previous id (find it in our list)
			if ((c->complete) && ((((ITEM_PORC_SESSION*)(c->item))->id_prev) == porc_packet_header.porc_session_id))
			{
				porc_session_id = c->id;
				porc_session = (ITEM_PORC_SESSION*)(c->item);
				break;
			}
		}

		if (porc_session_id == -1) {
			fprintf (stderr, "PORC session not found\n");
			return -1;
		}

		if (porc_session->client_tls_session != tls_session_id)
		{
			fprintf (stderr, "Wrong tls session\n");
			return -1;
		}
		printf ("first bytes of the encrypted payload : %08x\n", *(int *)payload);
		if (gcry_cipher_decrypt (porc_session->gcry_cipher_hd, payload, payload_length, NULL, 0)) {
			fprintf (stderr, "gcry_cipher_decrypt failed\n");
			return -1;
		}
		printf ("first bytes of the encrypted payload : %08x\n", *(int *)payload);
		if (porc_session->final == 0) 
		{
			//Rewrite paquet
			printf ("Rewrite packet\n");
			porc_packet_header.porc_session_id = porc_session_id;

			// Find TLS session
			ITEM_TLS_SESSION *next_tls_session;
			ChainedListFind (&tls_session_list, porc_session->server_tls_session, (void **)&next_tls_session);

			if (gnutls_record_send (next_tls_session->gnutls_session, (char *)&porc_packet_header, sizeof(porc_packet_header)) 
				!= sizeof(porc_packet_header))
			{
				fprintf (stderr, "Error forwarding header to next relay (router)\n");
				return -1;
			}
			if (gnutls_record_send (next_tls_session->gnutls_session, payload, payload_length) 
				!= payload_length)
			{
				fprintf (stderr, "Error forwarding payload to next relay (router)\n");
				return -1;
			}
		} 
		else // If we are the final relay
		{
			PORC_PAYLOAD_HEADER *porc_payload_header = (PORC_PAYLOAD_HEADER *)payload;
			int payload_content_length = payload_length - sizeof(PORC_PAYLOAD_HEADER);
			void *payload_content =  (void *)(payload+sizeof(PORC_PAYLOAD_HEADER));

			printf ("We are the final relay : (length, code) = (%d, %d)\n", porc_payload_header->length, porc_payload_header->code);
			
			if (porc_payload_header->code == PORC_COMMAND_TRANSMIT) {
				printf ("Received a transmit command\n");

				PORC_CONTENT_TRANSMIT *porc_content_transmit = (PORC_CONTENT_TRANSMIT *)payload_content;
				int message_length = payload_content_length - sizeof(PORC_CONTENT_TRANSMIT);
				char *message = payload_content + sizeof(PORC_CONTENT_TRANSMIT);

				// Find the SOCKS session
				CHAINED_LIST_LINK *c;
				for (c=socks_session_list.first; c!=NULL; c=c->nxt)
				{
					if (
						(((ITEM_SOCKS_SESSION *)(c->item))->client_porc_session ==
						porc_session_id)
					&& 	(((ITEM_SOCKS_SESSION *)(c->item))->id_prev ==
						porc_content_transmit->socks_session_id))
					{
						ITEM_SOCKS_SESSION *socks_session = (ITEM_SOCKS_SESSION *)(c->item);

						// Transmits the plain message
						if (send (socks_session->target_socket_descriptor,
							message, message_length, 0) != message_length)
						{
							fprintf (stderr, "Error forwarding to target (router)\n");
							return -1;
						}
					}
				}
			} else if (porc_payload_header->code == PORC_COMMAND_OPEN_SOCKS) {
				printf ("Received a open socks command\n");

				PORC_COMMAND_OPEN_SOCKS_CONTENT *porc_command_open_socks_content =
					(PORC_COMMAND_OPEN_SOCKS_CONTENT *)payload_content;

				int target_socket_descriptor = connect_to_host (
					htonl(porc_command_open_socks_content->ip),
					htons(porc_command_open_socks_content->port));
				if (target_socket_descriptor < 0)
				{
					fprintf (stderr, "Error connecting to host - socks - (final node)\n");
					return -1;
				}
				printf("Connection to host established\n");
				// Recode the socks session
				ITEM_SOCKS_SESSION *socks_session;
				int socks_session_id = ChainedListNew (&socks_session_list, (void **)&socks_session,
					sizeof(ITEM_SOCKS_SESSION));
				socks_session->id_prev = porc_command_open_socks_content->socks_session_id;
				socks_session->client_porc_session = porc_session_id;
				socks_session->target_socket_descriptor = target_socket_descriptor;
				ChainedListComplete (&socks_session_list, socks_session_id);
				// Send acknowledgment back to client
				PORC_RESPONSE_OPEN_SOCKS_CONTENT porc_response_open_socks_content;
				porc_response_open_socks_content.status = PORC_STATUS_SUCCESS;
				porc_response_open_socks_content.socks_session_id = socks_session->id_prev;
				if (relay_porc_send (PORC_RESPONSE_OPEN_SOCKS, porc_session->id_prev, (char *)&porc_response_open_socks_content,
					sizeof(porc_response_open_socks_content)) != 0)
				{
					fprintf (stderr, "Error sending ack for socks session opening(router)\n");
					return -1;
				}

				printf ("Ack sent for open socks\n");
				
				
				
				

			} else if (porc_payload_header->code == PORC_COMMAND_ASK_KEY) {

				printf ("Received an ask key command command\n");

				CHAINED_LIST_LINK *c;
				PORC_COMMAND_ASK_KEY_CONTENT *porc_command_ask_key_content =
					(PORC_COMMAND_ASK_KEY_CONTENT *)payload_content;
				int tls_session_id = -1;
				ITEM_TLS_SESSION *tls_session;

				for (c=tls_session_list.first; c!=NULL; c=c->nxt)
				{
					struct sockaddr_in peeraddr;
					if (c->complete == 1) {
						socklen_t peeraddrlen = sizeof(peeraddr);
						getpeername (((ITEM_TLS_SESSION *)(c->item))->socket_descriptor,
							(struct sockaddr *)&peeraddr, &peeraddrlen);
						if ((ntohl(peeraddr.sin_addr.s_addr) == porc_command_ask_key_content->ip)
							&& (ntohs(peeraddr.sin_port) == porc_command_ask_key_content->port))
						{
							printf ("Found and already open tls session.");
							tls_session_id = c->id;
							tls_session = (ITEM_TLS_SESSION *)(c->item);
							break;
						}
					}
				}

				if (tls_session_id == -1) {
					// Create a tls session

					printf ("Need to create a new tls connection\n");
					int socket_descriptor;
					gnutls_session_t gnutls_session;
					if (mytls_client_session_init (htonl(porc_command_ask_key_content->ip),
						htons(porc_command_ask_key_content->port), 
						&gnutls_session, &socket_descriptor) < 0) 
					{
						fprintf (stderr, "Error Connecting tls to relay\n");
						return -1;
					}

					tls_session_id = ChainedListNew (&tls_session_list, (void **)&tls_session,
						sizeof(ITEM_TLS_SESSION));
					tls_session->socket_descriptor = socket_descriptor;
					tls_session->gnutls_session = gnutls_session;
					ChainedListComplete (&tls_session_list, tls_session_id);

					// Record the tls session in the porc session
					porc_session->server_tls_session = tls_session_id;
				}

				// PROC handshake part I

				printf ("Send a public key request\n");
				PORC_HANDSHAKE_REQUEST porc_handshake_request;
				porc_handshake_request.command = PORC_HANDSHAKE_REQUEST_CODE;
				if (gnutls_record_send (tls_session->gnutls_session, (char *)&porc_handshake_request, 
					sizeof (porc_handshake_request)) != sizeof (porc_handshake_request))
				{
					fprintf (stderr, "Error in sending public key request (router)\n");
					return -1;
				}
				printf ("Public key requested\n");

				// Receive public key
				PORC_HANDSHAKE_KEY_HEADER porc_handshake_key_header;
				if (gnutls_record_recv (tls_session->gnutls_session, (char *)&porc_handshake_key_header,
					sizeof (porc_handshake_key_header)) != sizeof (porc_handshake_key_header))
				{
					fprintf (stderr, "Error receiving public key (router)\n");
					return -1;
				}
				if (porc_handshake_key_header.status != PORC_STATUS_SUCCESS) {
					fprintf (stderr, "Error receiving public key (router) : wrong status\n");
					return -1;
				}
				if ((porc_handshake_key_header.key_length <= 0) ||
					(porc_handshake_key_header.key_length > PORC_MAX_PACKET_LENGTH))
				{
					fprintf (stderr, "Error receiving public key (router) : wrong length\n");
					return -1;
				}
				printf ("public key length : %d\n", porc_handshake_key_header.key_length);
				int new_payload_length = sizeof (PORC_RESPONSE_ASK_KEY_CONTENT) + porc_handshake_key_header.key_length;
				char *new_payload = malloc (new_payload_length);
				char *public_key = new_payload + sizeof (PORC_RESPONSE_ASK_KEY_CONTENT);
				if (gnutls_record_recv (tls_session->gnutls_session, public_key, porc_handshake_key_header.key_length)
					!= porc_handshake_key_header.key_length)
				{
					fprintf (stderr, "Error receiving public key (router) : key transmission\n");
					return -1;
				}
				printf ("Received public key\n");

				// Send back public key
				PORC_RESPONSE_ASK_KEY_CONTENT *porc_response_ask_key_content = (PORC_RESPONSE_ASK_KEY_CONTENT *)new_payload;
				porc_response_ask_key_content->status = PORC_STATUS_SUCCESS;
				porc_response_ask_key_content->ip = porc_command_ask_key_content->ip;
				porc_response_ask_key_content->port = porc_command_ask_key_content->port;
				if (relay_porc_send (PORC_RESPONSE_ASK_KEY, porc_session->id_prev, new_payload,
					new_payload_length) != 0)
				{
					fprintf (stderr, "Error sending public key (router)\n");
					return -1;
				}

				free (new_payload);						
				printf ("Send public key\n");
			} else if (porc_payload_header->code == PORC_COMMAND_OPEN_PORC) {
				PORC_COMMAND_OPEN_PORC_HEADER *porc_command_open_porc_header = (PORC_COMMAND_OPEN_PORC_HEADER *)payload_content;

				// Find the TLS connection
				int tls_session_id = porc_session->server_tls_session;
				ITEM_TLS_SESSION *tls_session;
				ChainedListFind (&tls_session_list, tls_session_id, (void **)&tls_session);
				struct sockaddr_in peeraddr;
				socklen_t peeraddrlen = sizeof(peeraddr);
				getpeername (tls_session->socket_descriptor, (struct sockaddr *)&peeraddr, &peeraddrlen);
				if ((ntohl(peeraddr.sin_addr.s_addr) != porc_command_open_porc_header->ip)
					|| (ntohs(peeraddr.sin_port) != porc_command_open_porc_header->port))
				{
					printf ("Wrong ip/port in PORC_COMMAND_OPEN_PORC : %08x:%d vs %08x:%d.\n",
						ntohl(peeraddr.sin_addr.s_addr), ntohs(peeraddr.sin_port), porc_command_open_porc_header->ip,
						porc_command_open_porc_header->port);
					return -1;
				}

				// Send the crypted key

				int key_length = porc_payload_header->length - sizeof(PORC_PAYLOAD_HEADER)
					- sizeof(PORC_COMMAND_OPEN_PORC_HEADER);
				char *key = payload_content + sizeof(PORC_COMMAND_OPEN_PORC_HEADER);
				int new_payload_length = sizeof(PORC_HANDSHAKE_NEW) + key_length;
				char *new_payload = malloc (new_payload_length);
				char *key_in_new_payload = new_payload + sizeof(PORC_HANDSHAKE_NEW);


				PORC_HANDSHAKE_NEW *porc_handshake_new = (PORC_HANDSHAKE_NEW *)new_payload;
				porc_handshake_new->command = PORC_HANDSHAKE_NEW_CODE;
				porc_handshake_new->porc_session_id = porc_session_id;
				porc_handshake_new->key_length = key_length;
				printf ("key_length : %d\n", key_length);

				memcpy (key_in_new_payload, key, key_length);

				if (gnutls_record_send (tls_session->gnutls_session, new_payload, 
					new_payload_length) != new_payload_length)
				{
					fprintf (stderr, "Error in sending crypted key to next relay (router)\n");
					return -1;
				}

				free (new_payload);
				printf ("Crypted key sent\n");
				
				// Receive the acknowledgment
				PORC_HANDSHAKE_ACK porc_handshake_ack;
				if (gnutls_record_recv (tls_session->gnutls_session, (char *)&porc_handshake_ack, 
					sizeof(porc_handshake_ack)) != sizeof(porc_handshake_ack))
				{
					fprintf (stderr, "Error in receiving ack from next relay (router)\n");
					return -1;
				}
				if (porc_handshake_ack.status != PORC_STATUS_SUCCESS)
				{
					fprintf (stderr, "Error in receiving ack from next relay (router) : wrong status\n");
					return -1;
				}

				// Sending the ack
				PORC_RESPONSE_OPEN_PORC_CONTENT porc_response_open_porc_content;
				porc_response_open_porc_content.status = PORC_STATUS_SUCCESS;
				if (relay_porc_send (PORC_RESPONSE_OPEN_PORC, porc_session->id_prev, (char *)&porc_response_open_porc_content,
					sizeof(porc_response_open_porc_content)) != 0)
				{
					fprintf (stderr, "Error sending ack (router)\n");
					return -1;
				}

				printf ("Ack sent\n");

				// The relay is no longer final
				porc_session->final = 0;
				ChainedListComplete (&porc_session_list, porc_session->server_tls_session);
			} else if (porc_payload_header->code == PORC_COMMAND_CLOSE_SOCKS) {
				//

			} else if (porc_payload_header->code == PORC_COMMAND_CLOSE_PORC) {
				//
			} else {
				fprintf (stderr, "Wrong command\n");
				return -1;
			}
		}
	} else if (porc_packet_header.direction == PORC_DIRECTION_UP) {
		// We must encode
		printf ("direction is UP\n");

		CHAINED_LIST_LINK *c;
		porc_session_id = -1;
		for (c=porc_session_list.first; c!=NULL; c=c->nxt) 
		{
			//If we know it as a previous id (find it in our list)
			if ((c->complete) && (c->id == porc_packet_header.porc_session_id))
			{
				porc_session_id = c->id;
				porc_session = (ITEM_PORC_SESSION*)(c->item);
				break;
			}
		}

		if (porc_session_id == -1) {
			fprintf (stderr, "PORC session not found\n");
			return -1;
		}

		if (porc_session->server_tls_session != tls_session_id)
		{
			fprintf (stderr, "Wrong tls session (direction is DOWN)\n");
			return -1;
		}
		printf ("first bytes of the encrypted payload : %08x\n", *(int *)payload);
		if (gcry_cipher_encrypt (porc_session->gcry_cipher_hd, payload, payload_length, NULL, 0)) {
			fprintf (stderr, "gcry_cipher_decrypt failed\n");
			return -1;
		}
		printf ("first bytes of the encrypted payload : %08x\n", *(int *)payload);

		//Rewrite paquet
		printf ("Rewrite packet\n");
		porc_packet_header.porc_session_id = porc_session_id;

		// Find TLS session
		ITEM_TLS_SESSION *previous_tls_session;
		ChainedListFind (&tls_session_list, porc_session->client_tls_session, (void **)&previous_tls_session);

		if (gnutls_record_send (previous_tls_session->gnutls_session, (char *)&porc_packet_header, sizeof(porc_packet_header)) 
			!= sizeof(porc_packet_header))
		{
			fprintf (stderr, "Error forwarding header to next relay (router)\n");
			return -1;
		}
		if (gnutls_record_send (previous_tls_session->gnutls_session, payload, payload_length) 
			!= payload_length)
		{
			fprintf (stderr, "Error forwarding payload to next relay (router)\n");
			return -1;
		}
		printf ("Packet encoded and sent\n");
	}
	else 
	{
		fprintf (stderr, "Incorrect direction\n");
		free (payload);
		return -1;
	}

	free (payload);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////
// Gets packets from the socks session at the end of the tunnel and push them into the
// tunnel toward the client
////////////////////////////////////////////////////////////////////////////////////////
int send_to_porc(int socks_session_id) {
	// Get the current socks session
	printf("entering sendtoporc\n");
	ITEM_SOCKS_SESSION * socks_session;
	if (ChainedListFind (&socks_session_list, socks_session_id, (void **) &socks_session)!=0)
	{
		fprintf(stderr,"Error finding socks_session in send_to_porc\n");
		return -1;
	}
	int in_buffer_len = PORC_MAX_PACKET_LENGTH/2;
	char * in_buffer = malloc(in_buffer_len);
	//Read the socks stream
	in_buffer_len = recv(socks_session->target_socket_descriptor, in_buffer, in_buffer_len, 0);
	if (in_buffer_len<0)
	{
		fprintf(stderr,"Error reading socks packet %i : send_to_porc\n",in_buffer_len);
		return -1;
	}
	// If we get a closing signal
	if (in_buffer_len==0)
	{
			printf("closed stream\n");
			ChainedListRemove(&socks_session_list,socks_session_id);
			close(socks_session->target_socket_descriptor);
			return 0;
	}
	//Process it to add it to header information
	int out_buffer_len = in_buffer_len+sizeof(PORC_CONTENT_RETURN);
	char * out_buffer = malloc(out_buffer_len);
	PORC_CONTENT_RETURN * payload_header = malloc(sizeof(PORC_CONTENT_RETURN));
	payload_header->socks_session_id = socks_session_id;
	
	memcpy(out_buffer,payload_header,sizeof(PORC_CONTENT_RETURN));
	memcpy(out_buffer+sizeof(PORC_CONTENT_RETURN),in_buffer,in_buffer_len);	
	//Push it to the TOR stream
	printf("attemp to send socks packet to porc\n");
	if (relay_porc_send (PORC_RESPONSE_TRANSMIT, socks_session->client_porc_session, 
	out_buffer, out_buffer_len)!=0)
	{
		fprintf(stderr,"Error pushing SOCKS stream to TOR (tunnel end) : send_to_porc\n");
		return -1;
	}
	printf("packet sent\n");
	free(out_buffer);
	free(in_buffer);
	return 0;
}


////////////////////////////////////////////////////////////////////////////////////////
// 		Selecting
////////////////////////////////////////////////////////////////////////////////////////
int selecting() {
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
	for (;;) {
		while (set_fds (&nfds, &read_fds) <= 0) {
			sleep(1);
		}
		printf ("Beginning to select\n");
		if((nbr = pselect(nfds, &read_fds, 0, 0, 0, &signal_set)) > 0) {
			printf ("pselect returned %d\n", nbr);
			for (c=tls_session_list.first; c!=NULL; c=c->nxt) {
				if (FD_ISSET (((ITEM_TLS_SESSION *)(c->item))->socket_descriptor, &read_fds)) {
					printf ("tls session id : %d\n", c->id);
					if (process_porc_packet(c->id)!=0) {
						fprintf (stderr, "Stop (250), %d\n", c->id);
						return -1;
					}
				}
			}
			for (c=socks_session_list.first; c!=NULL; c=c->nxt) {
				if (FD_ISSET (((ITEM_SOCKS_SESSION*)(c->item))->target_socket_descriptor, &read_fds)) {
					printf ("socks session id : %d\n", c->id);
					if (send_to_porc(c->id)!=0) {
						fprintf (stderr, "Stop (270), %d\n", c->id);
						return -1;
					}
				}
			}
		}
	}

	return 0;
}
