/* ################################################################################

						Directory - PORC directory

		The PORC directory maintains a list of available and trusted PORC relays.

   ################################################################################*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h> 
#include <fcntl.h>
#include <errno.h>


#include "../lib/tls.h"
#include "../lib/tcp.h"
#include "../lib/porc_protocol.h"
#include "../config.h"

static gnutls_priority_t priority_cache;
static struct sockaddr_in sockaddr_server;
static int listen_socket_descriptor;

int nbr_relays;
MYSOCKET *list_relays;


/*
	handle_connection - Sets up a PORC connection and serves the list.
*/
void *handle_connection(void *arg) {
	int client_socket_descriptor = (int)arg;
	gnutls_session_t session;
	int ret;
	DIRECTORY_REQUEST directory_request;
	DIRECTORY_RESPONSE directory_response;

	gnutls_init (&session, GNUTLS_SERVER);
	gnutls_priority_set (session, priority_cache);
	gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);
	gnutls_certificate_server_set_request (session, GNUTLS_CERT_IGNORE);

	gnutls_transport_set_int (session, client_socket_descriptor);
	do {
		ret = gnutls_handshake (session);
	}
	while (ret < 0 && gnutls_error_is_fatal (ret) == 0);

	if (ret < 0) {
		close (client_socket_descriptor);
		gnutls_deinit (session);
		fprintf (stderr, "*** Handshake has failed (%s)\n\n", gnutls_strerror (ret));
		return NULL;
	}
	printf ("- Handshake was completed\n");

	if (gnutls_record_recv (session, (char *)&directory_request, sizeof (directory_request)) != sizeof (directory_request)) {
		close (client_socket_descriptor);
		gnutls_deinit (session);
		fprintf (stderr, "DIRECTORY handshake error (100)\n");
		return NULL;	
	}

	bzero ((void *)&directory_response, sizeof(directory_response));
	if (directory_request.command != DIRECTORY_ASK) {
		directory_response.status = DIRECTORY_FAILURE;
	} else {
		directory_response.status = DIRECTORY_SUCCESS;
		directory_response.nbr = nbr_relays;
	}
		
	if (gnutls_record_send (session, (char *)&directory_response, sizeof (directory_response))
		!= sizeof (directory_response))
	{
		close (client_socket_descriptor);
		gnutls_deinit (session);
		fprintf (stderr, "DIRECTORY handshake error (200)\n");
		return NULL;	
	}

	printf ("DIRECTORY handshake completed");
	if (directory_response.status == DIRECTORY_SUCCESS) {
		printf (" with success.\n");
	} else {
		printf (" with a failure.\n");
		close (client_socket_descriptor);
		gnutls_deinit (session);
		fprintf (stderr, "DIRECTORY handshake error (200)\n");
		return NULL;	
	}

	if (gnutls_record_send (session, (char *)list_relays, sizeof (MYSOCKET)*nbr_relays)
		!= sizeof (MYSOCKET)*nbr_relays)
	{
		close (client_socket_descriptor);
		gnutls_deinit (session);
		fprintf (stderr, "DIRECTORY error (300)\n");
		return NULL;	
	}

	close (client_socket_descriptor);
	printf ("Connection closed\n");

	return NULL;
}


/*
	main - Asks for a list of relays, initializes a TLS server and starts a thread for every client.
*/
int main (void)
{
	int client_socket_descriptor;
	struct sockaddr_in sockaddr_client;
	socklen_t client_adress_length;
	char topbuf[512];
	int ret;
	int file;
	struct stat fileinfo;

	ret = stat(FILE_LIST_RELAYS, &fileinfo);
	if (ret != 0) {
		fprintf (stderr, "Impossible to find file \"%s\"\n", FILE_LIST_RELAYS);
		return -1;
	}

	nbr_relays = fileinfo.st_size/sizeof(MYSOCKET);

	list_relays = malloc (nbr_relays*sizeof(MYSOCKET));

	file = open (FILE_LIST_RELAYS, O_RDONLY);
	if (file == -1) {
		ret = errno;
		fprintf (stderr, "Impossible to open \"%s\", errno = %d\n", FILE_LIST_RELAYS, ret);
		free (list_relays);
		return -1;
	}

	ret = read (file, list_relays, sizeof(MYSOCKET)*nbr_relays);
	if (ret != sizeof(MYSOCKET)*nbr_relays) {
		fprintf (stderr, "Error in reading : %d bytes read instead of %d\n", ret, sizeof(MYSOCKET)*nbr_relays);
		free (list_relays);
		return -1;
	}
	int i;
	for (i=0;i<nbr_relays;i++)
	{
		int ip = ((MYSOCKET*)list_relays)[i].ip;
		printf("Relay[%i], ip=%d.%d.%d.%d, port=%i\n",i,(ip) & 0xFF,(ip>>8) & 0xFF,
		(ip>>16) & 0xFF, (ip>>24) & 0xFF,ntohs(((MYSOCKET*)list_relays)[i].port));
	}

	close (file);

	printf ("%d trusted relays successfully read from file \"%s\"\n", nbr_relays, FILE_LIST_RELAYS);	

	if (mytls_server_init (DIRECTORY_PORT, &xcred, &priority_cache, &listen_socket_descriptor, &sockaddr_server, 0) != 0) {
		return -1;
	}

	client_adress_length = sizeof (sockaddr_client);
	for (;;) {
		client_socket_descriptor = accept (listen_socket_descriptor, (struct sockaddr *) &sockaddr_client, &client_adress_length);
		printf ("- connection from %s, port %d\n", inet_ntop (AF_INET, &sockaddr_client.sin_addr, topbuf, sizeof (topbuf)),
			ntohs(sockaddr_client.sin_port));

		pthread_t thread;
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		pthread_create(&thread, &attr, handle_connection, (void *)client_socket_descriptor);
	}
	close (listen_socket_descriptor);

	gnutls_certificate_free_credentials (xcred);
	gnutls_priority_deinit (priority_cache);

	gnutls_global_deinit ();

	free (list_relays);

	return 0;
}

