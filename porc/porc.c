#include "porc.h"

int nbr_relays = 0;
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



int set_symmetric_key (char **key_crypted, int *key_crypted_length, char *public_key, int public_key_length, int relay_index) {
	// import the key
	gcry_sexp_t sexp_public_key;
	printf ("we got to import : \n\"%s\"\n", public_key);
	if (gcry_sexp_new(sexp_public_key, public_key, public_key_length, 1)) 
	{
		fprintf(stderr,"Failed to import key\n");
		return -1;
	}
	printf("public key imported\n");
	
	// create the symmetric key
	char symmetric_key [CRYPTO_CIPHER_KEY_LENGTH];
	char init_vector [CRYPTO_CIPHER_BLOCK_LENGTH];
	gcry_randomize (symmetric_key, CRYPTO_CIPHER_KEY_LENGTH, GCRY_VERY_STRONG_RANDOM);
	gcry_randomize (init_vector, CRYPTO_CIPHER_BLOCK_LENGTH, GCRY_STRONG_RANDOM);
	if (gcry_cipher_open (&(client_circuit.gcry_cipher_hd[relay_index]), GCRY_CIPHER, GCRY_CIPHER_MODE_CBC, 0)) {
		fprintf (stderr, "gcry_cipher_open failed\n");
		return -1;
	}
	if (gcry_cipher_setkey (client_circuit.gcry_cipher_hd[relay_index], symmetric_key, CRYPTO_CIPHER_KEY_LENGTH) != 0) {
		fprintf (stderr, "gcry_cipher_setkey failed\n");
		return -1;
	}
	if (gcry_cipher_setiv (client_circuit.gcry_cipher_hd[relay_index], init_vector, CRYPTO_CIPHER_BLOCK_LENGTH) != 0) {
		fprintf (stderr, "gcry_cipher_setiv failed\n");
		return -1;
	}

	// Encrypt symmetric key with public key

	char key_plain [CRYPTO_CIPHER_KEY_LENGTH+CRYPTO_CIPHER_BLOCK_LENGTH];
	memcpy (key_plain+0, symmetric_key);
	memcpy (key_plain+CRYPTO_CIPHER_KEY_LENGTH, init_vector);

	gcry_sexp_t sexp_plain;
	gcry_sexp_t sexp_crypted;
	
	//String to SExpression Conversion
	gcry_mpi_t mpi_plain;
	size_t nbr_scanned;
	if (gcry_mpi_scan(&mpi_plain, GCRYMPI_FMT_USG, key_plain, CRYPTO_CIPHER_KEY_LENGTH+CRYPTO_CIPHER_BLOCK_LENGTH, &nbr_scanned) != 0)
	{
		fprintf (stderr, "Error while converting input from char to mpi, %i chars scanned", nbr_scanned);
		return -1;
	}
	if (gcry_sexp_build(&sexp_plain, NULL, "(data(flags raw)(value %m))", mpi_plain) != 0) 
	{
		printf( "Error while converting input from mpi to Sexpression");	 
		return -1;
	}
	gcry_mpi_release (mpi_plain);

	//Encryption
	if (gcry_pk_encrypt (&sexp_crypted, sexp_plain, sexp_public_key) != 0)
	{
		printf( "Error during the encryption" );
		return -1;
	}

	// SExpression to String Conversion
	*key_crypted_length = gcry_sexp_sprint (sexp_crypted, OUT_MODE, NULL, 0);
	*key_crypted = malloc (length_out);
	if(gcry_sexp_sprint(sexp_crypted, OUT_MODE, *key_crypted, *key_crypted_length) == 0) 
	{
		printf("Error while printing encrypted result");
		return -1;
	}
	gcry_sexp_release (sexp_crypted);
	gcry_sexp_release (sexp_plain);

	printf("key crypted\n");

	return 0;
}


int client_circuit_init (int circuit_length) {
	int directory_socket_descriptor;
	gnutls_session_t directory_gnutls_session;

	if (circuit_length > MAX_CIRCUIT_LENGTH) {
		fprintf (stderr, "Error in circuit length\n");
		return -1;
	}

	///////////////////////////////////////////////////////////////////////////////
	
	//			 Ask for the relay list to the PORC directory
	
	///////////////////////////////////////////////////////////////////////////////

	DIRECTORY_REQUEST directory_request;
	DIRECTORY_RESPONSE directory_response;

	if (mytls_client_session_init (inet_addr(DIRECTORY_IP), htons(DIRECTORY_PORT), 
		&directory_gnutls_session, &directory_socket_descriptor) < 0) 
	{
		fprintf (stderr, "Error joining directory\n");
		return -1;
	}

	directory_request.command = DIRECTORY_ASK;

	if (gnutls_record_send (directory_gnutls_session, (char *)&directory_request, 
		sizeof (directory_request)) != sizeof (directory_request)) 
	{
		fprintf (stderr, "directory request error (100)\n");
		close (directory_socket_descriptor);
		gnutls_deinit (directory_gnutls_session);
		return -1;	
	}

	if (gnutls_record_recv (directory_gnutls_session, (char *)&directory_response, 
		sizeof (directory_response)) != sizeof (directory_response))
	{
		fprintf (stderr, "directory request error (200)\n");
		close (directory_socket_descriptor);
		gnutls_deinit (directory_gnutls_session);
		return -1;
	}

	if (directory_response.status != DIRECTORY_SUCCESS) 
	{
		fprintf (stderr, "directory request error (300)\n");
		close (directory_socket_descriptor);
		gnutls_deinit (directory_gnutls_session);
		return -1;	
	}

	if (nbr_relays != 0) 
	{
		free (list_relays);
	}
	
	nbr_relays = directory_response.nbr;
	list_relays = (void *)malloc(sizeof(MYSOCKET)*nbr_relays);

	if (gnutls_record_recv (directory_gnutls_session, (char *)list_relays, sizeof(MYSOCKET)*nbr_relays)
		!= sizeof(MYSOCKET)*nbr_relays)
	{
		fprintf (stderr, "directory request error (400)\n");
		close (directory_socket_descriptor);
		gnutls_deinit (directory_gnutls_session);
		return -1;	
	}

	close (directory_socket_descriptor);
	gnutls_deinit(directory_gnutls_session);
	printf ("Received %d trusted relays.\n", nbr_relays);


	///////////////////////////////////////////////////////////////////////////////
	
	//							Creating the circuit
	
	///////////////////////////////////////////////////////////////////////////////

	// Select a random relay
	int r;
	gcry_randomize(&r,4,GCRY_STRONG_RANDOM);
	r = r % nbr_relays;		

	client_circuit.nbr_relays = 0;

	// Connect with tls to this relay
	if (mytls_client_session_init (list_relays[r].ip, list_relays[r].port,
		&(client_circuit.relay1_gnutls_session), &(client_circuit.relay1_socket_descriptor)) < 0) 
	{
		fprintf (stderr, "Error joining relay[0]\n");
		return -1;
	}

	// Make PORC handshake

	// Ask for public key
	PORC_HANDSHAKE_REQUEST porc_handshake_request;
	porc_handshake_request.command = PORC_HANDSHAKE_REQUEST_CODE;
	if (gnutls_record_send (client_circuit.relay1_gnutls_session, (char *)&porc_handshake_request, sizeof (porc_handshake_request))
		!= sizeof (porc_handshake_request)) 
	{
		fprintf (stderr, "Error Client requesting public key from Router[0]\n");
		return -1;	
	}
	//Wait for Public key
	PORC_HANDSHAKE_RESPONSE_HEADER porc_handshake_response_header;
	if (gnutls_record_recv (client_circuit.relay1_gnutls_session, (char *)&porc_handshake_response, sizeof (porc_handshake_response))
		!= sizeof (porc_handshake_response))
	{
		fprintf (stderr, "Error recieving public key from Router[0]\n");
		return -1;	
	}
	if (porc_handshake_response.status != PUB_KEY_SUCCESS)
	{
		fprintf (stderr, "Router[0] returned Error when asked for public key\n");
		return -1;
	}
	char *public_key = malloc (porc_handshake_response.length);
	if (gnutls_record_recv (client_circuit.relay1_gnutls_session, public_key, porc_handshake_response.length)
		!= sizeof (porc_handshake_response.length))
	{
		fprintf (stderr, "Error receiving public key from Router[0]\n");
		return -1;	
	}
	printf("public key received\n");

	char *key_crypted;
	int key_crypted_length;
	if (set_symmetric_key (&key_crypted, &key_crypted_length, public_key, porc_handshake_response.length, 0) {
		fprintf (stderr, "Error setting a key for Router[0]\n");
		return -1;
	}

	// Send Encripted SymmetricKey
	PORC_HANDSHAKE_NEW porc_handshake_new;
	porc_handshake_new.command = PORC_HANDSHAKE_NEW_CODE;
	porc_handshake_new.porc_session_id = 0;	
	porc_handshake_new.key_length = key_crypted_length;
	if (gnutls_record_send (client_circuit.relay1_gnutls_session, (char *)&porc_handshake_new, 
		sizeof (porc_handshake_new)) != sizeof (porc_handshake_new)) 
	{
		fprintf (stderr, "Error while sending Encrypted SumKey header to Router[0]\n");
		return -1;	
	}
	if (gnutls_record_send (client_circuit.relay1_gnutls_session, key_crypted, 
		key_crypted_length) != key_crypted_length) 
	{
		fprintf (stderr, "Error while sending Encrypted SumKey to Router[0]\n");
		return -1;	
	}
	free (key_crypted);

	PUBLIC_HANDLSHAKE_ACK porc_handshake_ack;
	if (gnutls_record_recv (client_circuit.relay1_gnutls_session, (char *)&porc_handshake_ack, sizeof (porc_handshake_ack))
		!= sizeof (porc_handshake_ack))
	{
		fprintf (stderr, "Error receiving acknowledgment from Router[0]\n");
		return -1;	
	}
	if (porc_handshake_ack.status != PUB_KEY_SUCCESS)
	{
		fprintf (stderr, "Router[0] returned Error as ACK\n");
		return -1;
	}
	client_circuit.length++;

	PORC_COMMAND command;
	PORC_RESPONSE response;
	int reponse_length;
	int router_index;
	for (router_index=1; router_index<client_circuit.nbr_relays; router_index++)
	{
		// Select a random relay
		int r;
		gcry_randomize(&r,4,GCRY_STRONG_RANDOM);
		r = r % nbr_relays;		

		// Ask for public key of next node
		PORC_COMMAND_ASK_KEY_CONTENT porc_command_ask_key_content;
		porc_command_ask_key_content.ip = htonl(list_relays[r].ip);
		porc_command_ask_key_content.port = htons(list_relays[r].port);
		if (porc_send (PORC_COMMAND_ASK_KEY, (char *)&porc_command_ask_key_content, sizeof (porc_command_ask_key_content)) != 0) 
		{
			return -1;	
		}

		//Wait for Public key
		PORC_RESPONSE_ASK_KEY_CONTENT *porc_response_ask_key_content;
		if (porc_recv (&response, (char *)&porc_response_ask_key_content, &response_length) != 0) {
		{
			fprintf (stderr, "Error recieving public key from Router[%i]\n",router_index);
			return -1;	
		}
		if (response != PORC_RESPONSE_ASK_KEY) {
		{
			fprintf (stderr, "Error recieving public key from Router[%i] : wrong response\n",router_index);
			return -1;	
		}
		if (response_length < sizeof(PORC_RESPONSE_ASK_KEY_CONTENT)) {
		{
			fprintf (stderr, "Error recieving public key from Router[%i] : too short\n",router_index);
			return -1;	
		}
		if (porc_response_ask_key_content->status != PORC_STATUS_SUCCESS)
		{
			fprintf (stderr, "Router[%i] returned Error when asked for public key\n",router_index);
			return -1;
		}
		if ((porc_response_ask_key_content->ip != porc_command_ask_key_content.ip) ||
			(porc_response_ask_key_content->port != porc_command_ask_key_content.port)) {
		{
			fprintf (stderr, "Wrong ip or port\n");
		}
		printf("public key received\n");

		if (set_symmetric_key (&key_crypted, &key_crypted_length, porc_response_ask_key_content+sizeof(PORC_RESPONSE_ASK_KEY_CONTENT),
			response_length-sizeof(PORC_RESPONSE_ASK_KEY_CONTENT), router_index)
		{
			fprintf (stderr, "Error setting a key for Router[%i]\n", router_index);
			return -1;
		}
		free(porc_response_ask_key_content);

		// Send the crypted symmetric key
		char *porc_content_open_porc = malloc(sizeof(PORC_CONTENT_OPEN_PORC_HEADER)+key_crypted_length);
		PORC_CONTENT_OPEN_PORC_HEADER *porc_content_open_porc_header = (PORC_CONTENT_OPEN_PORC_HEADER *)porc_content_open_porc;
		porc_content_open_porc->ip = porc_command_ask_key_content.ip;
		porc_content_open_porc->port = porc_command_ask_key_content.port;
		memcpy (porc_content_open_porc+sizeof(PORC_CONTENT_OPEN_PORC_HEADER), key_crypted, key_crypted_length);
		free (crypted_key);
		if (porc_send (PORC_COMMAND_OPEN_PORC, (char *)&porc_content_open_porc,
			sizeof(PORC_CONTENT_OPEN_PORC_HEADER)+key_crypted_length) != 0)
		{
			return -1;	
		}
		free (porc_content_open_porc);

		// Wait for a acknowlegdment
		PORC_RESPONSE_OPEN_PORC_CONTENT *porc_response_open_porc_content;
		if (porc_recv (&response, (char *)&porc_response_open_porc_content, &response_length) != 0) {
		{
			fprintf (stderr, "Error during acknowledgment from Router[%i]\n",router_index);
			return -1;	
		}
		if (response != PORC_RESPONSE_OPEN_PORC) {
		{
			fprintf (stderr, "Error during acknowledgment from Router[%i] : wrong response (2)\n",router_index);
			return -1;	
		}
		if (response_length < sizeof(PORC_RESPONSE_OPEN_PORC_CONTENT)) {
		{
			fprintf (stderr, "Error during acknowledgment from Router[%i] : too short\n",router_index);
			return -1;	
		}
		if (porc_response_open_porc_content->status != PORC_STATUS_SUCCESS)
		{
			fprintf (stderr, "Router[%i] returned Error as acknowledgment\n",router_index);
			return -1;
		}

		client_circuit.length++;
		printf ("--------------New relay---------\n");
		//Tunnel is now open to router[router_index]
	}

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


