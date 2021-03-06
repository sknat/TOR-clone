/* ################################################################################
							Client - PORC client

	The PORC client transfers a socks stream to a PORC circuit to the target.

   ################################################################################*/

#include "client_main.h"

pthread_t accepting_thread; // ACCEPT thread
pthread_t selecting_thread; // SELECT thread
CHAINED_LIST socks_session_list;
CLIENT_CIRCUIT client_circuit;
int nbr_relays = 0;
MYSOCKET *list_relays = NULL;

int client_porc_recv (PORC_RESPONSE *porc_response, char **payload, size_t *payload_length)
{
	PORC_PACKET_HEADER porc_packet_header;
	int ret;

	ret = gnutls_record_recv (client_circuit.relay1_gnutls_session, (char*)&porc_packet_header , sizeof(porc_packet_header));
	if (ret == 0) {
		fprintf (stderr, "Connection from PORC network closed unexpectedly\n");
		close(client_circuit.relay1_socket_descriptor);
		return -1;
	}
	if (ret < 0) {
		fprintf (stderr, "Failed to receive the header of the packet in client_porc_recv (1)\n");
		close(client_circuit.relay1_socket_descriptor);
		return -1;
	}
	if (ret != sizeof(porc_packet_header))
	{
		fprintf (stderr, "Failed to receive the header of the packet in client_porc_recv (2)\n");
		return -1;
	}
	if (porc_packet_header.length > PORC_MAX_PACKET_LENGTH) {
		fprintf (stderr, "Packet to long (client_porc_recv())\n");
		return -1;
	}
	if (porc_packet_header.length <= sizeof(PORC_PACKET_HEADER)) {
		fprintf (stderr, "Packet to short (client_porc_recv())\n");
		return -1;
	}
	if (porc_packet_header.direction != PORC_DIRECTION_UP) {
		fprintf (stderr, "Don't give me orders !\n");
		return -1;
	}
	if (porc_packet_header.porc_session_id != CLIENT_PORC_SESSION_ID) {
		fprintf (stderr, "Wrong PORC session id\n");
		return -1;
	}

	int porc_payload_length = porc_packet_header.length - sizeof(porc_packet_header);
	char *porc_payload = malloc(porc_payload_length);
	if(gnutls_record_recv (client_circuit.relay1_gnutls_session, porc_payload, porc_payload_length)
		!= porc_payload_length)
	{
		fprintf (stderr, "Failed to receive the payload in client_porc_recv()\n");
		return -1;
	}

	int i;
	for (i=0 ; i<client_circuit.length; i++)
	{
		printf ("initvect_index = %d\n", client_circuit.initvect_index[i]);
		client_circuit.initvect_index[i]++;
		if (gcry_cipher_decrypt(client_circuit.gcry_cipher_hd[i], porc_payload,
			porc_payload_length, NULL, 0))
		{
			fprintf (stderr, "gcry_cipher_decrypt failed\n");
			return -1;
		}
		gcry_cipher_reset (client_circuit.gcry_cipher_hd[i]);
	}

	PORC_PAYLOAD_HEADER *porc_payload_header = (PORC_PAYLOAD_HEADER *)porc_payload;

	if (porc_payload_header->length > porc_payload_length) {
		fprintf (stderr, "payload too long\n");
		return -1;
	}
	if (porc_payload_header->length <= 0) {
		fprintf (stderr, "payload too short\n");
		return -1;
	}

	*porc_response = porc_payload_header->code;

	*payload_length = porc_payload_header->length-sizeof(PORC_PAYLOAD_HEADER);
	*payload = malloc (*payload_length);
	memcpy (*payload, porc_payload+sizeof(PORC_PAYLOAD_HEADER), *payload_length);

	free (porc_payload);
	return 0;
}


int client_porc_send (PORC_COMMAND command, char *payload, size_t payload_length)
{
	int crypted_payload_length = ((sizeof(PORC_PAYLOAD_HEADER)+payload_length+CRYPTO_CIPHER_BLOCK_LENGTH-1)/
		CRYPTO_CIPHER_BLOCK_LENGTH)*CRYPTO_CIPHER_BLOCK_LENGTH;
	int porc_packet_length = sizeof(PORC_PACKET_HEADER) + crypted_payload_length;
	char *porc_packet = malloc(porc_packet_length);

	PORC_PACKET_HEADER *porc_packet_header = (PORC_PACKET_HEADER *)porc_packet;
	char *payload_in_packet = porc_packet + sizeof(PORC_PACKET_HEADER);
	PORC_PAYLOAD_HEADER *payload_header = (PORC_PAYLOAD_HEADER *)payload_in_packet;

	porc_packet_header->length = porc_packet_length;
	porc_packet_header->direction = PORC_DIRECTION_DOWN;
	porc_packet_header->porc_session_id = CLIENT_PORC_SESSION_ID;
	payload_header->code = command;
	payload_header->length = sizeof(PORC_PAYLOAD_HEADER)+payload_length;
	memcpy(payload_in_packet+sizeof(PORC_PAYLOAD_HEADER), payload, payload_length);
	memset (payload_in_packet+sizeof(PORC_PAYLOAD_HEADER)+payload_length, 'a',
		crypted_payload_length-(sizeof(PORC_PAYLOAD_HEADER)+payload_length));
	printf ("First payload bytes : %08x,%08x,%08x,%08x\n", *(int *)(payload+0), *(int *)(payload+4),
		*(int *)(payload+8), *(int *)(payload+12));
	printf ("length, code : %08x, %04x\n", payload_header->length, payload_header->code);
	printf ("First payload bytes : %08x,%08x,%08x,%08x\n", *(int *)(payload_in_packet+0), *(int *)(payload_in_packet+4),
		*(int *)(payload_in_packet+8), *(int *)(payload_in_packet+12));

	int i;
	for (i=client_circuit.length-1; i>=0; i--) {
		printf ("first bytes of the encrypted payload (i=%i) : %08x\n", i, *(int *)payload_in_packet);
		printf ("initvect index : %d\n", client_circuit.initvect_index[i]);
		client_circuit.initvect_index[i]++;
		if (gcry_cipher_encrypt(client_circuit.gcry_cipher_hd[i], payload_in_packet, crypted_payload_length, NULL, 0)) {
			fprintf (stderr, "gcry_cipher_encrypt failed\n");
			return -1;
		}
		gcry_cipher_reset (client_circuit.gcry_cipher_hd[i]);
	}
	printf ("first bytes of the encrypted payload (i=%i) : %08x\n", i, *(int *)payload_in_packet);

	if (gnutls_record_send (client_circuit.relay1_gnutls_session, porc_packet, porc_packet_length) != porc_packet_length)
	{
		fprintf (stderr, "Incorrect expected size to be sent in client_porc_send()\n");
		return -1;
	}

	free (porc_packet);
	return 0;
}



int set_symmetric_key (char **key_crypted, int *key_crypted_length, char *public_key, int public_key_length, int relay_index) {
	// import the key
	gcry_sexp_t sexp_public_key;
	printf ("we got to import : \n\"%s\"\n", public_key);
	if (gcry_sexp_new (&sexp_public_key, public_key, public_key_length, 1)) 
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
	if (gcry_cipher_open (&(client_circuit.gcry_cipher_hd[relay_index]), CRYPTO_CIPHER, GCRY_CIPHER_MODE_CBC, 0)) {
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
	gcry_cipher_reset (client_circuit.gcry_cipher_hd[relay_index]);
	client_circuit.initvect_index[relay_index]=0;

	printf ("first bytes of sym key : %d, %d, %d, %d\n", symmetric_key[0], symmetric_key[1], symmetric_key[2], symmetric_key[3]);

	// Encrypt symmetric key with public key

	char key_plain [CRYPTO_CIPHER_KEY_LENGTH+CRYPTO_CIPHER_BLOCK_LENGTH];
	memcpy (key_plain+0, symmetric_key, CRYPTO_CIPHER_KEY_LENGTH);
	memcpy (key_plain+CRYPTO_CIPHER_KEY_LENGTH, init_vector, CRYPTO_CIPHER_BLOCK_LENGTH);

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
	
	char *buffer = malloc (gcry_sexp_sprint(sexp_plain, GCRYSEXP_FMT_ADVANCED, NULL, 0));
	gcry_sexp_sprint(sexp_plain, GCRYSEXP_FMT_ADVANCED, buffer, gcry_sexp_sprint(sexp_plain, GCRYSEXP_FMT_ADVANCED, NULL, 0));
	printf ("plain sym key : \"%s\"\n", buffer);
	free (buffer);

	//Encryption
	if (gcry_pk_encrypt (&sexp_crypted, sexp_plain, sexp_public_key) != 0)
	{
		printf( "Error during the encryption" );
		return -1;
	}

	// SExpression to String Conversion
	*key_crypted_length = gcry_sexp_sprint (sexp_crypted, GCRYSEXP_FMT_ADVANCED, NULL, 0);
	*key_crypted = malloc (*key_crypted_length);
	if(gcry_sexp_sprint(sexp_crypted, GCRYSEXP_FMT_ADVANCED, *key_crypted, *key_crypted_length) == 0) 
	{
		printf("Error while printing encrypted result");
		return -1;
	}
	gcry_sexp_release (sexp_crypted);
	gcry_sexp_release (sexp_plain);

	printf("key crypted\n");

	return 0;
}


///////////////////////////////////////////////////////////////////////////////
//	
//			 Ask for the relay list to the PORC directory
//	
///////////////////////////////////////////////////////////////////////////////
int client_directory_create_list()
{
	int directory_socket_descriptor;
	gnutls_session_t directory_gnutls_session;
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
	return 0;
}

int open_porc_with_first_relay()
{
	// Select a random relay
	int r;
	//gcry_randomize(&r,4,GCRY_STRONG_RANDOM);
	r = 0;//r % nbr_relays;		

	// Connect with tls to this relay
	if (mytls_client_session_init (list_relays[r].ip, list_relays[r].port,
		&(client_circuit.relay1_gnutls_session), &(client_circuit.relay1_socket_descriptor)) < 0) 
	{
		fprintf (stderr, "Error joining relay[0]\n");
		return -1;
	}
	
	///////////////////////////
	//  Make PORC handshake  //
	///////////////////////////

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
	PORC_HANDSHAKE_KEY_HEADER porc_handshake_key_header;
	if (gnutls_record_recv (client_circuit.relay1_gnutls_session, (char *)&porc_handshake_key_header, sizeof (porc_handshake_key_header))
		!= sizeof (porc_handshake_key_header))
	{
		fprintf (stderr, "Error receiving public key from Router[0]\n");
		return -1;	
	}
	if (porc_handshake_key_header.status != PORC_STATUS_SUCCESS)
	{
		fprintf (stderr, "Router[0] returned Error when asked for public key\n");
		return -1;
	}
	if (porc_handshake_key_header.key_length > PORC_MAX_PACKET_LENGTH)
	{
		fprintf (stderr, "Router[0] returned Error when asked for public key : wrong length\n");
		return -1;
	}
	printf ("Public key length : %d\n", porc_handshake_key_header.key_length);
	char *public_key = malloc (porc_handshake_key_header.key_length);
	if (gnutls_record_recv (client_circuit.relay1_gnutls_session, public_key, porc_handshake_key_header.key_length)
		!= porc_handshake_key_header.key_length)
	{
		fprintf (stderr, "Error receiving public key from Router[0] (2)\n");
		return -1;	
	}
	printf("public key received\n");

	char *key_crypted;
	int key_crypted_length;
	if (set_symmetric_key (&key_crypted, &key_crypted_length, public_key, porc_handshake_key_header.key_length, 0) != 0) {
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
	printf ("crypted key length : %d\n", key_crypted_length);
	if (gnutls_record_send (client_circuit.relay1_gnutls_session, key_crypted, 
		key_crypted_length) != key_crypted_length) 
	{
		fprintf (stderr, "Error while sending Encrypted SumKey to Router[0]\n");
		return -1;	
	}
	free (key_crypted);
	printf ("Key crypted sent\n");

	PORC_HANDSHAKE_ACK porc_handshake_ack;
	if (gnutls_record_recv (client_circuit.relay1_gnutls_session, (char *)&porc_handshake_ack, sizeof (porc_handshake_ack))
		!= sizeof (porc_handshake_ack))
	{
		fprintf (stderr, "Error receiving acknowledgment from Router[0]\n");
		return -1;	
	}
	if (porc_handshake_ack.status != PORC_STATUS_SUCCESS)
	{
		fprintf (stderr, "Router[0] returned Error as ACK\n");
		return -1;
	}
	return 0;
}

int open_porc_with_next_relay(int relay_id)
{
	PORC_RESPONSE response;
	size_t response_length;
	// Select a random relay
	int r;
	//gcry_randomize(&r,4,GCRY_STRONG_RANDOM);
	r = relay_id;//r % nbr_relays;		

	// Ask for public key of next node
	printf ("Ask for public key\n");
	PORC_COMMAND_ASK_KEY_CONTENT porc_command_ask_key_content;
	porc_command_ask_key_content.ip = htonl(list_relays[r].ip);
	porc_command_ask_key_content.port = htons(list_relays[r].port);
	printf ("request key for (ip, port) = (%08x, %i)\n", porc_command_ask_key_content.ip, porc_command_ask_key_content.port);
	if (client_porc_send (PORC_COMMAND_ASK_KEY, (char *)&porc_command_ask_key_content, sizeof (porc_command_ask_key_content)) != 0) 
	{
		return -1;	
	}

	// Wait for Public key
	printf ("Wait for public key\n");
	PORC_RESPONSE_ASK_KEY_CONTENT *porc_response_ask_key_content;
	if (client_porc_recv (&response, (char **)&porc_response_ask_key_content, &response_length) != 0)
	{
		fprintf (stderr, "Error recieving public key from Router[%i]\n",relay_id);
		return -1;	
	}
	if (response != PORC_RESPONSE_ASK_KEY)
	{
		fprintf (stderr, "Error recieving public key from Router[%i] : wrong response\n",relay_id);
		return -1;	
	}
	if (response_length < sizeof(PORC_RESPONSE_ASK_KEY_CONTENT))
	{
		fprintf (stderr, "Error recieving public key from Router[%i] : too short\n",relay_id);
		return -1;	
	}
	if (porc_response_ask_key_content->status != PORC_STATUS_SUCCESS)
	{
		fprintf (stderr, "Router[%i] returned Error when asked for public key\n",relay_id);
		return -1;
	}
	if ((porc_response_ask_key_content->ip != porc_command_ask_key_content.ip) ||
		(porc_response_ask_key_content->port != porc_command_ask_key_content.port))
	{
		fprintf (stderr, "Wrong ip or port\n");
	}
	printf("public key received\n");

	char *key_crypted;
	int key_crypted_length;
	if (set_symmetric_key (&key_crypted, &key_crypted_length,
		(char *)porc_response_ask_key_content+sizeof(PORC_RESPONSE_ASK_KEY_CONTENT),
		response_length-sizeof(PORC_RESPONSE_ASK_KEY_CONTENT), relay_id))
	{
		fprintf (stderr, "Error setting a key for Router[%i]\n", relay_id);
		return -1;
	}
	free(porc_response_ask_key_content);

	// Send the crypted symmetric key
	printf ("Send the sym key\n");
	char *porc_command_open_porc = malloc(sizeof(PORC_COMMAND_OPEN_PORC_HEADER)+key_crypted_length);
	PORC_COMMAND_OPEN_PORC_HEADER *porc_command_open_porc_header = (PORC_COMMAND_OPEN_PORC_HEADER *)porc_command_open_porc;
	porc_command_open_porc_header->ip = porc_command_ask_key_content.ip;
	porc_command_open_porc_header->port = porc_command_ask_key_content.port;
	memcpy (porc_command_open_porc+sizeof(PORC_COMMAND_OPEN_PORC_HEADER), key_crypted, key_crypted_length);
	free (key_crypted);
	printf ("ip, port : %08x, %04x\n", porc_command_open_porc_header->ip, porc_command_open_porc_header->port);
	printf ("First payload bytes : %08x,%08x,%08x,%08x\n", *(int *)(porc_command_open_porc+0), *(int *)(porc_command_open_porc+4),
		*(int *)(porc_command_open_porc+8), *(int *)(porc_command_open_porc+12));
	if (client_porc_send (PORC_COMMAND_OPEN_PORC, (char *)porc_command_open_porc,
		sizeof(PORC_COMMAND_OPEN_PORC_HEADER)+key_crypted_length) != 0)
	{
		return -1;	
	}
	free (porc_command_open_porc);

	// Wait for an acknowlegdment
	printf ("Wait for ack\n");
	PORC_RESPONSE_OPEN_PORC_CONTENT *porc_response_open_porc_content;
	if (client_porc_recv (&response, (char **)&porc_response_open_porc_content, &response_length) != 0)
	{
		fprintf (stderr, "Error during acknowledgment from Router[%i]\n",relay_id);
		return -1;	
	}
	if (response != PORC_RESPONSE_OPEN_PORC)
	{
		fprintf (stderr, "Error during acknowledgment from Router[%i] : wrong response (2)\n",relay_id);
		return -1;	
	}
	if (response_length < sizeof(PORC_RESPONSE_OPEN_PORC_CONTENT))
	{
		fprintf (stderr, "Error during acknowledgment from Router[%i] : too short\n",relay_id);
		return -1;	
	}
	if (porc_response_open_porc_content->status != PORC_STATUS_SUCCESS)
	{
		fprintf (stderr, "Router[%i] returned Error as acknowledgment\n",relay_id);
		return -1;
	}
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
//
//							Creates the Porc circuit
//
///////////////////////////////////////////////////////////////////////////////
int client_circuit_init (int circuit_length) 
{
	client_circuit.length = 0;
	if (circuit_length > MAX_CIRCUIT_LENGTH) 
	{
		fprintf (stderr, "Error in circuit length\n");
		return -1;
	}
	if (client_directory_create_list()!=0)
	{
		fprintf (stderr, "Error while asking directory for relays\n");
		return -1;
	}
	if (open_porc_with_first_relay()!=0)
	{
		fprintf (stderr, "Error while contacting first relay\n");
		return -1;
	}
	printf ("--------------New relay %i---------\n", client_circuit.length);
	client_circuit.length = 1;
	int relay_id;
	for (relay_id=1; relay_id<circuit_length; relay_id++)
	{
		if (open_porc_with_next_relay(relay_id)!=0)
		{
			fprintf (stderr, "Error while contacting relay[%i]\n",relay_id);
			return -1;
		}
		printf ("--------------New relay %i---------\n", client_circuit.length);
		client_circuit.length++;
		//Tunnel is now open to router[router_index]
	}

	printf ("PORC circuit set up\n");
	return 0;
}

int client_circuit_free () {
/*
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
*/
	return 0;
}


//The proxy method to be runned in a thread
void *start_proxy(void *arg){
	return ((void *)proxy_socksv4 ((int)arg));
}

int main () {
	// gcrypt initialisation
	if (!gcry_check_version (GCRYPT_VERSION)) {
		fprintf (stderr, "libgcrypt version mismatch\n");
		return -1;
	}
	gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
	gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);	


	if (signal_init () != 0) {
		fprintf (stderr, "Error in signals initialisation\n");
		return -1;
	}

	if ((mytls_client_global_init (&xcred))<0) {
		fprintf (stderr, "Error in mytls_client_global_init()\n");
		return -1;
	}

	// Set up the connection to the PORC network
	if (client_circuit_init (PORC_TUNNEL_RELAY_NUM) != 0) {
		fprintf (stderr, "Error in circuit initialisation\n");
		gnutls_certificate_free_credentials (xcred);
		gnutls_global_deinit ();
		return -1;
	}

	printf("Socks sessions init\n");
	ChainedListInit (&socks_session_list);

	printf("Creation of the proxy thread\n");
	//Creates a thread to run the client proxy
	selecting_thread = pthread_self ();
	
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(&accepting_thread, &attr, start_proxy, (void*)CLIENT_PORT) != 0) 
	{
		fprintf (stderr, "Thread creation failed\n");
		client_circuit_free ();
		gnutls_certificate_free_credentials (xcred);
		gnutls_global_deinit ();
		return -1;
	}
	//Runs the socks proxy
	do_proxy ();
	//Deinit everything
	client_circuit_free ();
	gnutls_certificate_free_credentials (xcred);
	gnutls_global_deinit ();

	return 0;
}

