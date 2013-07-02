/* ################################################################################
							
							Relay - PORC relay

					Methods for accepting connections

   ################################################################################*/

#include "accept.h"


////////////////////////////////////////////////////////////////////////////////////////
//	handle_connection - Sets up a TLS and a PORC session with a client or relay.
////////////////////////////////////////////////////////////////////////////////////////
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
	
	// Record TLS session
	ITEM_TLS_SESSION *tls_session;
	int tls_session_id = ChainedListNew (&tls_session_list, (void**) &tls_session, sizeof(ITEM_TLS_SESSION));
	tls_session->socket_descriptor = client_socket_descriptor;
	tls_session->gnutls_session = gnutls_session;
	printf ("tls_session %d created, gnutls_session : %d\n", (int)tls_session, (int)gnutls_session);

	// Start a PORC session
	// wait for asking public key
	PORC_HANDSHAKE_REQUEST porc_hanshake_request;
	if (gnutls_record_recv (gnutls_session, (char *)&porc_hanshake_request, 
		sizeof (porc_hanshake_request)) != sizeof (porc_hanshake_request))
	{
		fprintf (stderr, "Error in public key request (router)\n");
		return -1;
	}
	printf ("Public key requested\n");
	if (porc_hanshake_request.command != PORC_HANDSHAKE_REQUEST_CODE)
	{
		fprintf (stderr, "Error : invalid public key request\n");
		return -1;
	}
	printf ("Valid public key request\n");

	// Send public Key

	int public_key_length = gcry_sexp_sprint (public_key, GCRYSEXP_FMT_ADVANCED, NULL, 0);
	printf ("key length : %d\n", public_key_length);

	int message_length = sizeof(PORC_HANDSHAKE_KEY_HEADER)+public_key_length;
	char *message = malloc (message_length);
	PORC_HANDSHAKE_KEY_HEADER *porc_handshake_key_header = (PORC_HANDSHAKE_KEY_HEADER *)message;

	if (gcry_sexp_sprint(public_key, GCRYSEXP_FMT_ADVANCED, message+sizeof(PORC_HANDSHAKE_KEY_HEADER), public_key_length) < 0) 
	{
		fprintf(stderr, "Error while exporting key\n");
		free (message);
		return -1;
	}

	printf ("public key : \"%s\"\n", message+sizeof(PORC_HANDSHAKE_KEY_HEADER));

	porc_handshake_key_header->status = PORC_STATUS_SUCCESS;
	porc_handshake_key_header->key_length = public_key_length;
	if (gnutls_record_send (gnutls_session, message, message_length) != message_length)
	{
		fprintf (stderr, "Error sending public key (router)\n");
		return -1;
	}
	printf ("Sent public key\n");
	free(message);


	// Wait for the symmetric key
	PORC_HANDSHAKE_NEW porc_handshake_new;
	if (gnutls_record_recv (gnutls_session, (char *)&porc_handshake_new, 
		sizeof (porc_handshake_new)) != sizeof (porc_handshake_new)) 
	{
		fprintf (stderr, "Error while awaiting symmetric key\n");
		return -1;	
	}
	if (porc_handshake_new.command != PORC_HANDSHAKE_NEW_CODE)
	{
		fprintf (stderr, "Error : invalid command\n");
		return -1;
	}
	if (porc_handshake_new.key_length > 1024)
	{
		fprintf (stderr, "Error : crypted key too long\n");
		return -1;
	}
	printf ("crypted key length : %d\n", porc_handshake_new.key_length);
	char *crypted_key = malloc (porc_handshake_new.key_length);
	if (gnutls_record_recv (gnutls_session, crypted_key, 
		porc_handshake_new.key_length) != porc_handshake_new.key_length) 
	{
		fprintf (stderr, "Error while awaiting symmetric key (2)\n");
		return -1;	
	}
	printf ("Received sym key : \"%s\"\n", crypted_key);

	

	// Decrypt the sym key

	gcry_sexp_t sexp_plain;
	gcry_sexp_t sexp_crypted;

	if (gcry_sexp_new(&sexp_crypted, crypted_key, porc_handshake_new.key_length, 1) != 0) 
	{
		fprintf (stderr, "Error while reading the encrypted data\n");	
		return -1;
	}
	printf ("New sexp_crypted\n");
	if (gcry_pk_decrypt (&sexp_plain, sexp_crypted, private_key) != 0) 
	{
		fprintf (stderr, "Error during the decryption\n");
		return -1;
	}
	printf ("gcry_pk_decrypt ok\n");
	int key_plain_length = gcry_sexp_sprint (sexp_plain, GCRYSEXP_FMT_ADVANCED, NULL, 0);
	printf ("key_plain_length = %d\n", key_plain_length);
	char *key_plain = malloc (key_plain_length);
	if (gcry_sexp_sprint (sexp_plain, GCRYSEXP_FMT_ADVANCED, key_plain, key_plain_length) == 0)
	{
		fprintf (stderr, "Error while printing decryption result\n");
		return -1;
	}

	printf ("plain key : \"%s\"\n", key_plain);

	free (crypted_key);
	gcry_sexp_release(sexp_crypted);
	gcry_sexp_release(sexp_plain);

	// Convert hex representation to natural representation
	int i;
	int j;
	for (i=1; (i<key_plain_length) && (key_plain[i]!='#'); i++) {}
	if (i==2*(CRYPTO_CIPHER_KEY_LENGTH+CRYPTO_CIPHER_BLOCK_LENGTH)+1) {
		j = 0;
	} else if (i==2*(CRYPTO_CIPHER_KEY_LENGTH+CRYPTO_CIPHER_BLOCK_LENGTH)+3) {
		j = 2;
	} else {
		fprintf (stderr, "Wrong sym key representation\n");
		return -1;
	}
	for (i=j+1; i<j+1+2*(CRYPTO_CIPHER_KEY_LENGTH+CRYPTO_CIPHER_BLOCK_LENGTH); i++) {
		if ((key_plain[i] >= 'A') && (key_plain[i] <= 'F')) {
			key_plain[i] = key_plain[i] - 'A' + 10;
		} else if ((key_plain[i] >= '0') && (key_plain[i] <= '9')) {
			key_plain[i] = key_plain[i] - '0';
		} else {
			fprintf (stderr, "Error processing sym key\n");
			return -1;
		}
	}
	for (i=0; i<CRYPTO_CIPHER_KEY_LENGTH+CRYPTO_CIPHER_BLOCK_LENGTH; i++) {
		key_plain[i] = key_plain[1+j+2*i]*16 + key_plain[1+j+2*i+1];
	}

	printf ("sym key decrypted\n");
	printf ("first bytes of sym key : %d, %d, %d, %d\n", key_plain[0], key_plain[1], key_plain[2], key_plain[3]);

	// Create a gcrypt context
	gcry_cipher_hd_t gcry_cipher_hd;
	if (gcry_cipher_open (&gcry_cipher_hd, CRYPTO_CIPHER, GCRY_CIPHER_MODE_CBC, 0)) {
		fprintf (stderr, "gcry_cipher_open failed\n");
		return -1;
	}
	if (gcry_cipher_setkey (gcry_cipher_hd, key_plain, CRYPTO_CIPHER_KEY_LENGTH) != 0) {
		fprintf (stderr, "gcry_cipher_setkey failed\n");
		return -1;
	}
	if (gcry_cipher_setiv (gcry_cipher_hd, key_plain+CRYPTO_CIPHER_KEY_LENGTH, CRYPTO_CIPHER_BLOCK_LENGTH) != 0) {
		fprintf (stderr, "gcry_cipher_setiv failed\n");
		return -1;
	}

	free (key_plain);

	PORC_HANDSHAKE_ACK porc_handshake_ack;
	porc_handshake_ack.status = PORC_STATUS_SUCCESS;
	if (gnutls_record_send (gnutls_session, (char *)&porc_handshake_ack, sizeof(porc_handshake_ack)) != sizeof(porc_handshake_ack))
	{
		fprintf (stderr, "Error sending acknowledgment (router)\n");
		return -1;
	}	

	// Record the PORC session
	ITEM_PORC_SESSION *porc_session;
	int porc_session_id;
	porc_session_id = ChainedListNew (&porc_session_list, (void *)&porc_session, sizeof(ITEM_PORC_SESSION));
	porc_session->id_prev = porc_handshake_new.porc_session_id;
	porc_session->client_tls_session = tls_session_id;
	porc_session->gcry_cipher_hd = gcry_cipher_hd;
	porc_session->final = 1;
	porc_session->server_tls_session = 0;

	// PORC session is ready
	ChainedListComplete (&porc_session_list, porc_session_id);
	printf ("porc session %d recorded\n", porc_session_id);

	// TLS session is ready
	ChainedListComplete (&tls_session_list, tls_session_id);
	printf ("tls_session %d recorded, gnutls_session : %d\n", (int)tls_session, (int)gnutls_session);

	// Signaling a new available socket to the selecting thread
	if (pthread_kill (selecting_thread, SIGUSR1) != 0) {
		fprintf (stderr, "Signal sending failed\n");
		return -1;
	}
	printf ("----------DONE ACCEPTING CONNECTION---------\n");

	return 0;
}


////////////////////////////////////////////////////////////////////////////////////////
//	Accepting : Method to be runned in a thread that accepts new connections
////////////////////////////////////////////////////////////////////////////////////////
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
	

