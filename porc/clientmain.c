#include "clientmain.h"
#include "porc.c"
#include "signaling.c"

pthread_t accepting_thread; // ACCEPT thread
pthread_t selecting_thread; // SELECT thread

//The proxy method to be runned in a thread
void *start_proxy(void *arg){
	return ((void *)proxy_socksv4 ((int)arg));
}

int main () {
	if (signal_init () != 0) {
		fprintf (stderr, "Error in signals initialisation\n");
		return -1;
	}

	if ((mytls_client_global_init (&xcred))<0) {
		fprintf (stderr, "Error in mytls_client_global_init()\n");
		return -1;
	}

	// Set up the connection to the PORC network
	if (client_circuit_init () != 0) {
		fprintf (stderr, "Error in circuit initialisation\n");
		gnutls_certificate_free_credentials (xcred);
		gnutls_global_deinit ();
		return -1;
	}

	ChainedListInit (&porc_sessions);

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

