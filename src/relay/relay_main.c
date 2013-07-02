/* ################################################################################

								Relay - PORC relay

		The PORC relay transfers a stream to another relay or to the target.

   ################################################################################*/


#include "relay_main.h"

gnutls_priority_t priority_cache;

pthread_t accepting_thread;
pthread_t selecting_thread;

gcry_sexp_t public_key; 
gcry_sexp_t private_key;


CHAINED_LIST tls_session_list;
CHAINED_LIST porc_session_list;
CHAINED_LIST socks_session_list;

////////////////////////////////////////////////////////////////////////////////////////
// 		Main - Initializes a TLS server and starts a thread for every client.
////////////////////////////////////////////////////////////////////////////////////////
int main (int argc, char **argv)
{
	int listen_socket_descriptor;
	struct sockaddr_in sockaddr_server;
	int port;
	int ret;

	// gcrypt initialisation
	if (!gcry_check_version (GCRYPT_VERSION)) {
		fprintf (stderr, "libgcrypt version mismatch\n");
		return -1;
	}
	gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
	gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);	

	// assymmetric keys creation

	gcry_sexp_t key_specification;
	gcry_sexp_t key;
	
	if(gcry_sexp_new(&key_specification, "(genkey (rsa (nbits 4:2048)))", 0, 1) != 0)
	{
		fprintf (stderr, "Error creating S-expression for RSA keys\n");
		return -1;
	}

	if (gcry_pk_genkey (&key, key_specification) != 0)
	{
		fprintf (stderr, "Error while generating RSA key.\n");
		return -1;
	}
	gcry_sexp_release (key_specification);
	
	if (!(public_key = gcry_sexp_find_token (key, "public-key", 0))) 
	{
		fprintf (stderr, "Error seeking for public part in key.\n");
		return -1;
	}
	if (!(private_key = gcry_sexp_find_token( key, "private-key", 0 ))) 
	{
		fprintf (stderr, "Error seeking for private part in key.\n");
		return -1;
	}
	gcry_sexp_release(key);
	
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


