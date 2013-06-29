/***********************************************************************************
	Relay - PORC relay

	The PORC relay transfers a stream to another relay or to the target.

***********************************************************************************/

#include "relaymain.h"

static gnutls_priority_t priority_cache;

pthread_t accepting_thread;
pthread_t selecting_thread;

gcry_sexp_t publicKey; 
gcry_sexp_t privateKey;


CHAINED_LIST tls_session_list;
CHAINED_LIST porc_session_list;
CHAINED_LIST socks_session_list;

/* ################################################################################

							ACCEPTING CONNECTIONS

################################################################################ */

/***********************************************************************************
	handle_connection - Sets up a TLS and a PORC session with a client or relay.
***********************************************************************************/
int handle_connection(int client_socket_descriptor) {
	gnutls_session_t gnutls_session;
	int ret;

	gnutls_init (&gnutls_session, GNUTLS_SERVER);
	gnutls_priority_set (gnutls_session, priority_cache);
	gnutls_credentials_set (gnutls_session, GNUTLS_CRD_CERTIFICATE, xcred);
	gnutls_certificate_server_set_request (gnutls_session, GNUTLS_CERT_IGNORE);

	gnutls_transport_set_int (gnutls_session, client_socket_descriptor);
	do {
		ret = gnutls_handshake (gnutls_session);
	}
	while (ret < 0 && gnutls_error_is_fatal (ret) == 0);

	if (ret < 0) {
		close (client_socket_descriptor);
		gnutls_deinit (gnutls_session);
		fprintf (stderr, "*** Handshake has failed (%s)\n\n", gnutls_strerror (ret));
		return -1;
	}
	printf ("Tls handshake was completed\n");
	
	// Start a PORC session
	// wait for asking public key
	PUB_KEY_REQUEST pub_key_request;
	if (gnutls_record_recv (gnutls_session, (char *)&pub_key_request, 
		sizeof (pub_key_request)) != sizeof (pub_key_request))
	{
		fprintf (stderr, "Error in public key request (router)\n");
		return -1;
	}
	printf ("Public key requested\n");
	if (pub_key_request.command != PUB_KEY_ASK)
	{
		fprintf (stderr, "Error : invalid public key request\n");
		return -1;
	}
	printf ("Valid request\n");
	//Send public Key
	PUB_KEY_RESPONSE pub_key_response;
	char * export_pub_key = malloc(PUBLIC_KEY_LEN);
	if (rsaExportKey(&publicKey, export_pub_key)!=0)
	{
		fprintf (stderr, "Error exporting public key (router)\n");
		return -1;
	}
	printf ("Exported public key\n");
	pub_key_response.status = PUB_KEY_SUCCESS;
	memcpy(pub_key_response.public_key,export_pub_key,PUBLIC_KEY_LEN);
	if (gnutls_record_send (gnutls_session, (char *)&pub_key_response, 
		sizeof (pub_key_response)) != sizeof (pub_key_response))
	{
		fprintf (stderr, "Error sending public key (router)\n");
		return -1;
	}
	printf ("Sent public key\n");
	free(export_pub_key);
	//Wait for the symmetric key
	CRYPT_SYM_KEY_RESPONSE crypt_sym_key_response;
	ret = gnutls_record_recv (gnutls_session, (char *)&crypt_sym_key_response, 
		sizeof (crypt_sym_key_response));
	if (ret != sizeof (crypt_sym_key_response)) 
	{
		fprintf (stderr, "Error while awaiting symmetric key (router) size=%i awaited=%i\n",sizeof (crypt_sym_key_response),ret);
		return -1;	
	}
	printf ("We got sym key\n");
	if (crypt_sym_key_response.status != CRYPT_SYM_KEY_SUCCESS)
	{
		fprintf (stderr, "Error : invalid symmetric key\n");
		return -1;
	}
	printf ("Valid container for sym key\n");
	
	char sym_key[SYM_KEY_LEN];
	if (rsaDecrypt(crypt_sym_key_response.crypt_sym_key,CRYPT_SYM_KEY_LEN, sym_key, privateKey)<0)
	{
		fprintf (stderr, "Error decrypting symmetric key\n");
		return -1;
	}
	printf ("sym key decrypted\n");

	// Record TLS session
	ITEM_TLS_SESSION * tls_session;
	int tls_session_id = ChainedListNew (&tls_session_list, (void**) &tls_session, sizeof(ITEM_TLS_SESSION));
	tls_session->socket_descriptor = client_socket_descriptor;
	tls_session->gnutls_session = gnutls_session;

		
	// Record the PORC session
	ITEM_PORC_SESSION *porc_session;
	int porc_session_id;
	porc_session_id = ChainedListNew (&porc_session_list, (void *)&porc_session, sizeof(ITEM_PORC_SESSION));
	porc_session->id_prev = pub_key_request.porc_session; 
	porc_session->client_tls_session = tls_session_id;
	porc_session->final = 1;
	porc_session->server_tls_session = 0;
	memcpy(porc_session->sym_key, sym_key, SYM_KEY_LEN);

	printf ("Porc session %d recorded\n", porc_session_id);
	sleep(2);
	// Signaling a new available socket to the selecting thread
	if (pthread_kill (selecting_thread, SIGUSR1) != 0) {
		fprintf (stderr, "Signal sending failed\n");
		return -1;
	}
	printf ("----------DONE ACCEPTING CONNECTION---------\n");

	return 0;
}
/***********************************************************************************
	Accepting : Method to be runned in a thread that accepts new connections
***********************************************************************************/
int accepting (int listen_socket_descriptor) {
	struct sockaddr_in sockaddr_client;
	int client_socket_descriptor;
	socklen_t length = sizeof(sockaddr_client);
	int ret;

	for (;;) {
		if ((client_socket_descriptor = accept(listen_socket_descriptor, (struct sockaddr *) &sockaddr_client, &length)) > 0) {
			printf ("New client , socket_descriptor = '%d'\n", client_socket_descriptor);
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
	

/* ################################################################################

							PROCESSING CONNECTIONS

################################################################################ */

int set_fds (int *nfds, fd_set *fds) {
	CHAINED_LIST_LINK *c;
	int max = -2;
	int n=0;
	
	FD_ZERO (fds); //Initialize set
	
	for (c=tls_session_list.first; c!= NULL; c=c->nxt) {
		FD_SET (((ITEM_TLS_SESSION*)(c->item))->socket_descriptor, fds);
		n++;
		if (((ITEM_TLS_SESSION*)(c->item))->socket_descriptor > max) {
			max = ((ITEM_TLS_SESSION*)(c->item))->socket_descriptor;
		}
	}

	for (c=socks_session_list.first; c!=NULL; c=c->nxt) {
		FD_SET (((ITEM_SOCKS_SESSION*)(c->item))->target_socket_descriptor, fds);
		n++;
		if (((ITEM_SOCKS_SESSION*)(c->item))->target_socket_descriptor > max) {
			max = ((ITEM_SOCKS_SESSION*)(c->item))->target_socket_descriptor;
		}
	}
	*nfds = max + 1;
	return n;	
}



int process_porc_packet(int tls_session_id) {
	
	ITEM_TLS_SESSION * tls_session;
	gnutls_session_t gnutls_session;
	
	ChainedListFind (&tls_session_list, tls_session_id, (void**)&tls_session);
	gnutls_session = tls_session->gnutls_session;

	printf ("A packet to process for the PORC network...\n");

	// Read the number of bytes
	int length;
	if (gnutls_record_recv (gnutls_session, (char *)&length, sizeof(length))
		!= sizeof (length))
	{
		fprintf (stderr, "Impossible to read the length of the PORC packet\n");
		return -1;
	}

	printf ("length : %d\n", length);

	// Read the remainder of the packet
	char *buffer = malloc (length-sizeof(length));
	if (gnutls_record_recv (gnutls_session, buffer, length-sizeof(length))
		!= length-sizeof (length))
	{
		fprintf (stderr, "Impossible to read the PORC packet\n");
		return -1;
	}

	int direction = *(int *)(buffer+0);			// Read the direction
	int porc_received_id = *(int *)(buffer+4);		// Read the PORC session

	int porc_session_id;
	ITEM_PORC_SESSION * porc_session;
	
	if (direction == PORC_DIRECTION_DOWN) {
		// We must decode

		CHAINED_LIST_LINK *c;
		for (c=porc_session_list.first; c!=NULL; c=c->nxt) {
			//If we know it as a previous id (find it in our list)
			if ((((ITEM_PORC_SESSION*)(c->item))->id_prev) == porc_received_id)
			{
				porc_session_id = c->id;
				porc_session = (ITEM_PORC_SESSION*)(c->item);

				if (porc_session->client_tls_session != tls_session_id)
				{
					fprintf (stderr, "Wrong tls session\n");
					return -1;
				}
				if(aesImportKey(porc_session->sym_key, SYM_KEY_LEN)!=0)
				{
					fprintf(stderr,"Failed to import SYMKEY for encoding/decoding message (router)");
					return -1;
				}
				size_t newsize = aesDecrypt(buffer+2*sizeof(int),length-sizeof(length)-2*sizeof(int));
				if (porc_session->final == 0) 
				{
					int sent_length = newsize + 2*sizeof(int)+sizeof(length);
					//Rewrite paquet
					((int *)buffer)[1] = porc_session_id;	
					if (gnutls_record_send (gnutls_session, (char *)&sent_length, sizeof(sent_length)) 
						!= sizeof(sent_length))
					{
						fprintf (stderr, "Error forwarding length to next relay (router)\n");
						return -1;
					}
					if (gnutls_record_send (gnutls_session, (char *)&buffer, sent_length-sizeof(sent_length)) 
						!= sent_length-sizeof(sent_length))
					{
						fprintf (stderr, "Error forwarding message to next relay (router)\n");
						return -1;
					}
				} 
				else //IF we are the final one
				{
					char * message = malloc(newsize);
					memcpy(message,buffer+2*sizeof(int),newsize);
					int command = ((int* )message)[0];
					if (command == PORC_COMMAND_TRANSMIT)
					{
						printf ("Received a transmit command\n");
						ITEM_TLS_SESSION * next_tls_session;
						ChainedListFind (&tls_session_list, porc_session->server_tls_session ,
							(void **) &next_tls_session);
						if (gnutls_record_send (tls_session->gnutls_session, (char *)buffer+sizeof(int), 
							newsize-sizeof(int)) != newsize-sizeof(int))
						{
							fprintf (stderr, "Error transmitting final message (final node)\n");
							return -1;
						}
					}
					if (command == PORC_COMMAND_OPEN_SOCKS)
					{
						printf ("Received a open socks command\n");
						uint32_t open_socks_ip = ntohl(*((uint32_t* )(message+4)));
						uint16_t open_socks_port = ntohl(*((uint16_t* )(message+8)));
						uint32_t open_socks_prev_id = ntohl(*((uint32_t* )(message+10)));
						int target_socket_descriptor = connect_to_host(htonl(open_socks_ip), htons(open_socks_port));
						if (target_socket_descriptor < 0)
						{
							fprintf (stderr, "Error connecting to host - socks - (final node)\n");
							return -1;
						}
						ITEM_SOCKS_SESSION * socks_session;
						ChainedListNew(&socks_session_list, (void **)&socks_session, sizeof(ITEM_SOCKS_SESSION));
						socks_session->id_prev = open_socks_prev_id;
						socks_session->client_porc_session = c->id;
						socks_session->target_socket_descriptor = target_socket_descriptor;
					}
					if (command == PORC_COMMAND_OPEN_PORC)
					{
						gnutls_session_t target_gnutls_session;
						printf ("Received a open porc command\n");
						uint32_t open_porc_ip = ntohl(*((uint32_t* )(message+4)));
						uint16_t open_porc_port = ntohl(*((uint16_t* )(message+8)));
						int target_socket_descriptor;
						if (mytls_client_session_init (htonl(open_porc_ip), htons(open_porc_port), 
							&target_gnutls_session, &target_socket_descriptor) < 0) 
						{
							fprintf (stderr, "Error Connecting tls for router\n");
							return -1;
						}
						ITEM_TLS_SESSION * target_tls_session;
						int target_tls_session_id = ChainedListNew(&tls_session_list, (void **)&target_tls_session,
							sizeof(ITEM_TLS_SESSION));
						if (target_tls_session_id<0)
						{
							fprintf (stderr, "ChainList Errror\n");
							return -1;
						}
						target_tls_session->socket_descriptor = target_socket_descriptor;
						target_tls_session->gnutls_session = target_gnutls_session;
						
						porc_session->server_tls_session = tls_session_id;
						porc_session->final = 0;
					}
					if (command == PORC_COMMAND_CLOSE_SOCKS)
					{
						//
					}
					if (command == PORC_COMMAND_CLOSE_PORC)
					{
						//
					}
				}
				return 0;
			}
		}
	} else if (direction == PORC_DIRECTION_UP) {
		// We must encode

		CHAINED_LIST_LINK *c;
		for (c=porc_session_list.first; c!=NULL; c=c->nxt) 
		{
			//If we know it as a previous id (find it in our list)
			if (c->id == porc_received_id)
			{
				porc_session = (ITEM_PORC_SESSION*)(c->item);
				if (porc_session->client_tls_session != tls_session_id)
				{
					fprintf (stderr, "Wrong tls session\n");
					return -1;
				}
				// Encode and send to the previous relay
				if(aesImportKey(porc_session->sym_key,SYM_KEY_LEN)!=0)
					{
						fprintf(stderr,"Failed to import SYMKEY for encoding/decoding message (router)");
						return -1;
					}
				size_t newsize = aesEncrypt(buffer+2*sizeof(int),length-sizeof(length)-2*sizeof(int));
				length = newsize + 2*sizeof(int)+sizeof(length);
				// Encode and send to the next relay
				((int *)buffer)[1] = porc_session->id_prev;	
					if (gnutls_record_send (gnutls_session, (char *)&length, sizeof(length)) 
						!= sizeof(length))
					{
						fprintf (stderr, "Error forwarding length to next relay (router)\n");
						return -1;
					}
					if (gnutls_record_send (gnutls_session, (char *)&buffer, length-sizeof(length)) 
						!= length-sizeof(length))
					{
						fprintf (stderr, "Error forwarding message to next relay (router)\n");
						return -1;
					}				
			}
			return 0;
		}
	}
	else 
	{
		fprintf (stderr, "Incorrect direction\n");
		return -1;
	}

	fprintf (stderr, "Incorrect PORC session.\n");
	return -1;
}

int send_to_porc(int socks_session_id) {
	// Send a packet from a target to a relay.


	return 0;
}

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
	printf ("Beginning to select\n");
	for (;;) {
		while (set_fds (&nfds, &read_fds) <= 0) {
			sleep(1);
		}
		if((nbr = pselect(nfds, &read_fds, 0, 0, 0, &signal_set)) > 0) {
			printf ("pselect returned a negative integer\n");
			for (c=tls_session_list.first; c!=NULL; c=c->nxt) {
				if (FD_ISSET (((ITEM_TLS_SESSION *)(c->item))->socket_descriptor, &read_fds)) {
					if (process_porc_packet(c->id)!=0) {
						fprintf (stderr, "Stop (250), %d\n", c->id);
						return -1;
					}
				}
			}
			for (c=socks_session_list.first; c!=NULL; c=c->nxt) {
				if (FD_ISSET (((ITEM_SOCKS_SESSION*)(c->item))->target_socket_descriptor, &read_fds)) {
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


/*
	main - Initializes a TLS server and starts a thread for every client.
*/

int main (int argc, char **argv)
{
	int listen_socket_descriptor;
	struct sockaddr_in sockaddr_server;
	int port;
	int ret;

	if (rsaInit()!=0) 
	{
		fprintf(stderr, "Error initializing RSA\n");
		return -1;
	}

	if (rsaGenKey(&publicKey, &privateKey)!=0) 
	{
		fprintf(stderr, "Error initializing RSA Keys\n");
		return -1;
	}
	
	if (argc != 2) {
		fprintf (stderr, "Incorrect number of argument : you must define a port to listen to\n");
		return -1;
	}

	port = atoi (argv[1]);

	if ((ret=signal_init()) != 0) {
		fprintf (stderr, "Error in signals initialisation\n");
		return -1;
	}

	if ((ret=mytls_server_init (port, &xcred, &priority_cache, &listen_socket_descriptor, 
	&sockaddr_server,1))!=0) 
	{
		fprintf (stderr, "Error in mytls_client_global_init()\n");
		return -1;
	}

	ChainedListInit (&tls_session_list);
	ChainedListInit (&porc_session_list);
	ChainedListInit (&socks_session_list);
	//Starts the selecting Thread
	selecting_thread = pthread_self ();
	//Starts the accepting Thread
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


