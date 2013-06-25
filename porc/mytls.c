#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/x509.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "config.h"
#include "mytls.h"

/*
	_verify_certificate_callback - Checks the validity of the certificate during the TLS handshake.
*/
static int _verify_certificate_callback (gnutls_session_t session);
gnutls_certificate_credentials_t xcred;

int mytls_client_global_init ()
{
	int ret;

	if ((ret=gnutls_global_init ()) < 0) {
		fprintf (stderr, "Error in gnutls_global_init : %s\n", gnutls_strerror(ret));
	}

	if ((ret=gnutls_certificate_allocate_credentials (&xcred)) < 0) {
		fprintf (stderr, "Error in gnutls_certificate_allocate_credentials : %s\n", gnutls_strerror(ret));
	}

	// sets the trusted CAs file
	if ((ret=gnutls_certificate_set_x509_trust_file (xcred, ROOT_CA_FILE, GNUTLS_X509_FMT_PEM))<0) {
		fprintf (stderr, "Error in gnutls_certificate_set_x509_trust_file : %s\n", gnutls_strerror(ret));
	}

	// certificate is verified during handshake
	gnutls_certificate_set_verify_function (xcred, _verify_certificate_callback);

	return 0;
}

int mytls_client_session_init (uint32_t ip, uint16_t port,
	gnutls_session_t *session, int *socket_descriptor)
{
	int ret;
	const char *err;
	struct sockaddr_in sockaddr_server;

	// Initialize TLS session
	gnutls_init (session, GNUTLS_CLIENT);

	// Use default priorities
	ret = gnutls_priority_set_direct (*session, "NORMAL", &err);
	if (ret < 0) {
		if (ret == GNUTLS_E_INVALID_REQUEST) {
			fprintf (stderr, "Syntax error at: %s\n", err);
		}
		gnutls_deinit (*session);
		return -1;
	}

	// put the x509 credentials to the current session
	gnutls_credentials_set (*session, GNUTLS_CRD_CERTIFICATE, xcred);

	// connect to the peer

	*socket_descriptor = socket (AF_INET, SOCK_STREAM, 0);

	memset (&sockaddr_server, '\0', sizeof (sockaddr_server));
	sockaddr_server.sin_family = AF_INET;
	sockaddr_server.sin_addr.s_addr = ip;
	sockaddr_server.sin_port = port;

	ret = connect (*socket_descriptor, (struct sockaddr *) &sockaddr_server, sizeof (sockaddr_server));
	if (ret < 0) {
		fprintf (stderr, "Impossible to connect to the peer.\n");
		gnutls_deinit (*session);
		return -1;
	}


	gnutls_transport_set_int (*session, *socket_descriptor);
	gnutls_handshake_set_timeout (*session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	// Perform the TLS handshake
	do {
		ret = gnutls_handshake (*session);
	} while (ret < 0 && gnutls_error_is_fatal (ret) == 0);

	if (ret < 0) {
		fprintf (stderr, "*** Handshake failed\n");
		gnutls_perror (ret);
		close (*socket_descriptor);
		gnutls_deinit (*session);
		return -1;
	}

	return 0;
}


static int _verify_certificate_callback (gnutls_session_t session) {
	unsigned int status;
	int ret, type;
	gnutls_datum_t out;

	ret = gnutls_certificate_verify_peers3 (session, NULL, &status);
	if (ret < 0) {
		printf ("Error\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	type = gnutls_certificate_type_get (session);

	ret = gnutls_certificate_verification_status_print( status, type, &out, 0);
	if (ret < 0) {
		printf ("Error\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	printf ("%s\n", out.data);

	gnutls_free(out.data);

	if (status != 0) /* Certificate is not trusted */
		return GNUTLS_E_CERTIFICATE_ERROR;

	// notify gnutls to continue handshake normally
	return 0;
}




int mytls_server_init (int port, gnutls_certificate_credentials_t *xcred, gnutls_priority_t *priority_cache, int *listen_socket_descriptor,
	struct sockaddr_in *sockaddr_server)
{
	int ret;
	int optval = 1;

	// this must be called once in the program
	gnutls_global_init ();

	gnutls_certificate_allocate_credentials (xcred);

	ret = gnutls_certificate_set_x509_key_file (*xcred, CERT_FILE, KEY_FILE, GNUTLS_X509_FMT_PEM);

	if (ret < 0) {
		printf("No certificate or key were found\n");
		exit(1);
	}

	gnutls_priority_init (priority_cache, "PERFORMANCE:%SERVER_PRECEDENCE", NULL);

	// Socket operations

	*listen_socket_descriptor = socket (AF_INET, SOCK_STREAM, 0);

	memset (sockaddr_server, '\0', sizeof (*sockaddr_server));
	sockaddr_server->sin_family = AF_INET;
	sockaddr_server->sin_addr.s_addr = INADDR_ANY;
	sockaddr_server->sin_port = htons (port);

	setsockopt (*listen_socket_descriptor, SOL_SOCKET, SO_REUSEADDR, (void *) &optval, sizeof (int));

	bind (*listen_socket_descriptor, (struct sockaddr *) sockaddr_server, sizeof (*sockaddr_server));

	listen (*listen_socket_descriptor, 1024);

	printf ("Server ready. Listening to port '%d'.\n", port);

	return 0;
}
