#include "porc.h"

int nbr_relays = 0;
int nbr_tunnel_relays = 3;
char keytable[MAX_TUNNEL_RELAYS][SYM_KEY_LEN];
int presentkeys = 0;


MYSOCKET *list_relays = NULL;

int porc_record_recv (gnutls_session_t session, char * msg, size_t expectedsize)
	{
		if (presentkeys!=0)
		{
			int size;
			if (gnutls_record_recv (session, (char*) &size , sizeof(int))!=sizeof(int))
			{
				fprintf (stderr, "Incorrect expected size to be received\n");
				return -1;
			}
			if (expectedsize!=size)
			{
				fprintf (stderr, "Incorrect size, not that expected\n");
				return -1;
			}
			char * in = malloc(size);
			if(gnutls_record_recv (session, in, size)!=size)
			{
				fprintf (stderr, "Incorrect size, not that expected\n");
				return -1;
			}
			memcpy(msg,in+2*sizeof(int),size-2*sizeof(int));
			size = size - 2*sizeof(int);
			int i;			
			for (i=0 ; i<presentkeys ; i++)
			{
				aesImportKey(keytable[i],SYM_KEY_LEN);
				size = aesDecrypt(msg,size);
			}
			return size;
		}
		else
		{
			int i;
			gnutls_record_recv (session, msg, expectedsize);
			for (i=0 ; i<presentkeys ; i++)
			{
				aesImportKey(keytable[i],SYM_KEY_LEN);
				expectedsize = aesDecrypt(msg,expectedsize);
			}
			return expectedsize;
		}
	}
	
int porc_record_send (gnutls_session_t session, char * msg, size_t size)
	{
		if (presentkeys!=0)
		{
			int i;
			for (i=presentkeys ; i>0 ; i--)
			{
				aesImportKey(keytable[i],SYM_KEY_LEN);
				size = aesEncrypt(msg,size);
			}
			char * out = malloc(size+2*sizeof(int));
			((int *)out)[0] = PORC_DIRECTION_UP;
			((int *)out)[1] = 0;
			memcpy(out+2*sizeof(int),msg,size);
			size = size+2;
			if (gnutls_record_send (session, (char*) size , sizeof(size))!=sizeof(size))
			{
				fprintf (stderr, "Incorrect expected size to be sent\n");
				return -1;
			}
			return (gnutls_record_send (session, msg, size));
		}
		else
		{
			int i;
			for (i=presentkeys ; i>0 ; i--)
			{
				aesImportKey(keytable[i],SYM_KEY_LEN);
				size = aesEncrypt(msg,size);
			}
			return (gnutls_record_send (session, msg, size));
		}
	}


int client_circuit_init () {
	int socket_descriptor;
	gnutls_session_t session;

	///////////////////////////////////////////////////////////////////////////////
	
	//			 Ask for the relay list to the PORC directory
	
	///////////////////////////////////////////////////////////////////////////////

	DIRECTORY_REQUEST directory_request;
	DIRECTORY_RESPONSE directory_response;

	if (mytls_client_session_init (inet_addr(DIRECTORY_IP), htons(DIRECTORY_PORT), 
		&session, &socket_descriptor) < 0) 
	{
		fprintf (stderr, "Error joining directory\n");
		return -1;
	}

	directory_request.command = DIRECTORY_ASK;

	if (gnutls_record_send (session, (char *)&directory_request, 
		sizeof (directory_request)) != sizeof (directory_request)) 
	{
		fprintf (stderr, "directory request error (100)\n");
		close (socket_descriptor);
		gnutls_deinit (session);
		return -1;	
	}

	if (gnutls_record_recv (session, (char *)&directory_response, 
		sizeof (directory_response)) != sizeof (directory_response))
	{
		fprintf (stderr, "directory request error (200)\n");
		close (socket_descriptor);
		gnutls_deinit (session);
		return -1;
	}

	if (directory_response.status != DIRECTORY_SUCCESS) 
	{
		fprintf (stderr, "directory request error (300)\n");
		close (socket_descriptor);
		gnutls_deinit (session);
		return -1;	
	}

	if (nbr_relays != 0) 
	{
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
	///////////////////////////////////////////////////////////////////////////////
	
	//							Creating the circuit
	
	///////////////////////////////////////////////////////////////////////////////
	rsaInit();
	aesInit();
	int router_index;
	for (router_index = 0 ; router_index < nbr_tunnel_relays ; router_index++)
	{
		//session : the current session
		//socket_descriptor : the current socket
		
		// Select a random relay
		int r;
		gcry_randomize(&r,4,GCRY_STRONG_RANDOM);
		r = r % nbr_relays;		
		//Connect with tls to this relay
		if (mytls_client_session_init (list_relays[r].ip, list_relays[r].port,
			&session, &socket_descriptor) < 0) 
		{
			fprintf (stderr, "Error joining relay[%i]\n",router_index);
			return -1;
		}
		// Memorize the first relay
		if (router_index==0)
		{
			client_circuit.session = session;
			client_circuit.relay1_socket_descriptor = socket_descriptor;
		}
		//Ask for public key of next node
		PUB_KEY_REQUEST pub_key_request;
		pub_key_request.command = PUB_KEY_ASK;
		pub_key_request.porc_session = 0;
		if (porc_record_send (session, (char *)&pub_key_request, 
			sizeof (pub_key_request)) != sizeof (pub_key_request)) 
		{
			fprintf (stderr, "Error Client requesting public key from Router[%i]\n",router_index);
			close (socket_descriptor);
			gnutls_deinit (session);
			return -1;	
		}
		//Wait for Public key
		PUB_KEY_RESPONSE pub_key_response;
		if (porc_record_recv (session, (char *)&pub_key_response, 
			sizeof (pub_key_response)) != sizeof (pub_key_response))
		{
			fprintf (stderr, "Error recieving public key from Router[%i]\n",router_index);
			close (socket_descriptor);
			gnutls_deinit (session);
			return -1;	
		}
		printf("public key received\n");
		if (pub_key_response.status != PUB_KEY_SUCCESS)
		{
			fprintf (stderr, "Router[%i] returned Error when asked for public key\n",router_index);
			close (socket_descriptor);
			gnutls_deinit (session);
			return -1;
		}
		printf("success\n");
		//The public key is stored in pub_key_response->public_key
		//Encrypt symmetricKey with publicKey
		aesGenKey();
		char * cryptClientSymKey = malloc(CRYPT_SYM_KEY_LEN);
		printf("aeskeygen\n");
		aesExportKey(keytable[router_index]);
		printf("aesexport\n");
		gcry_sexp_t pubkey;
		printf("we got to import : %s\n",pub_key_response.public_key);
		if (rsaImportKey((char*) (pub_key_response.public_key),PUBLIC_KEY_LEN, &pubkey )!=0)
		{
			fprintf (stderr, "Error importing public key given by router\n");
			close (socket_descriptor);
			gnutls_deinit (session);
			return -1;
		}
		printf("public key imported\n");
		rsaEncrypt(keytable[router_index],SYM_KEY_LEN, cryptClientSymKey, pubkey );
		
		printf("public key crypted\n");
		//Send Encripted SymmetricKey
		CRYPT_SYM_KEY_RESPONSE crypt_sym_key_response;
		crypt_sym_key_response.status = CRYPT_SYM_KEY_SUCCESS;
		memcpy(crypt_sym_key_response.crypt_sym_key,cryptClientSymKey,PUBLIC_KEY_LEN);
		if (porc_record_send (session, (char *)&crypt_sym_key_response, 
			sizeof (crypt_sym_key_response)) != sizeof (crypt_sym_key_response)) 
		{
			fprintf (stderr, "Error while sending Encrypted SumKey to Router[%i]\n",router_index);
			close (socket_descriptor);
			gnutls_deinit (session);
			return -1;	
		}
		presentkeys++;
		printf("--------------Circuit CREATED--------- %i keys\n",presentkeys);
		//Tunnel is now open to router[router_index]
	}

	close (socket_descriptor);
	gnutls_deinit (session);
	printf ("PORC circuit set up\n");
	return 0;
}

int client_circuit_free () {
	while (presentkeys>0)
	{
		char * msg = malloc(sizeof(int));
		((int*)msg)[0] = PORC_COMMAND_CLOSE_PORC;
		size_t cSize = sizeof(int);
		int i;
		for (i=presentkeys ; i>0 ; i--)
		{
			aesImportKey(keytable[i],SYM_KEY_LEN);
			cSize = aesEncrypt(msg,cSize);
		}
		char * hd_msg = malloc(cSize+2*sizeof(int));
		((int*)hd_msg)[0] = PORC_DIRECTION_UP;
		((int*)hd_msg)[1] = 0; //ID of packet
		memcpy(hd_msg+2*sizeof(int),msg,cSize);
		if (gnutls_record_send (client_circuit.session, (char *)&cSize, sizeof(int)) 
			!= sizeof(int)) {
			fprintf (stderr, "Error closing circuit -- sending size of packet\n");
			close (client_circuit.relay1_socket_descriptor);
			gnutls_deinit (client_circuit.session);
			return -1;	
		}
		if (gnutls_record_send (client_circuit.session, hd_msg, cSize+2*sizeof(int)) 
			!= cSize+2*sizeof(int)) {
			fprintf (stderr, "Error closing circuit -- sending packet\n");
			close (client_circuit.relay1_socket_descriptor);
			gnutls_deinit (client_circuit.session);
			return -1;	
		}
	presentkeys--;
	}
	close (client_circuit.relay1_socket_descriptor);
	gnutls_deinit (client_circuit.session);

	return 0;
}


