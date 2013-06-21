#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>

#include "config.h"

#define MAX_BUF 1024

static gnutls_dh_params_t dh_params;

int start_router_server (void)
{
	int listen_sd;
	int sd, ret, type;
	gnutls_certificate_credentials_t xcred;
	gnutls_priority_t priority_cache;
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	socklen_t client_len;
	char topbuf[512];
	gnutls_session_t session;
	char buffer[MAX_BUF + 1];
	int optval = 1;
	unsigned int status;
	gnutls_datum_t out;

	// this must be called once in the program
	gnutls_global_init ();

	gnutls_certificate_allocate_credentials (&xcred);

	gnutls_certificate_set_x509_trust_file (xcred, ROOT_CA_FILE, GNUTLS_X509_FMT_PEM);

	ret = gnutls_certificate_set_x509_key_file (xcred, SERV_CERT_FILE, SERV_KEY_FILE, GNUTLS_X509_FMT_PEM);

	if (ret < 0) {
		printf("No certificate or key were found\n");
		exit(1);
	}

	gnutls_priority_init (&priority_cache, "PERFORMANCE:%SERVER_PRECEDENCE", NULL);

	// Socket operations

	listen_sd = socket (AF_INET, SOCK_STREAM, 0);

	memset (&sa_serv, '\0', sizeof (sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons (SERV_PORT);      /* Server Port number */

	setsockopt (listen_sd, SOL_SOCKET, SO_REUSEADDR, (void *) &optval, sizeof (int));

	bind (listen_sd, (struct sockaddr *) & sa_serv, sizeof (sa_serv));

	listen (listen_sd, 1024);

	printf ("Server ready. Listening to port '%d'.\n\n", SERV_PORT);

	client_len = sizeof (sa_cli);
	for (;;) {
		gnutls_init (&session, GNUTLS_SERVER);
		gnutls_priority_set (session, priority_cache);
		gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

		gnutls_certificate_send_x509_rdn_sequence (session, 1);
		gnutls_certificate_server_set_request (session, GNUTLS_CERT_REQUIRE);

		sd = accept (listen_sd, (struct sockaddr *) & sa_cli, &client_len);

		printf ("- connection from %s, port %d\n", inet_ntop (AF_INET, &sa_cli.sin_addr, topbuf, sizeof (topbuf)), ntohs (sa_cli.sin_port));

		gnutls_transport_set_int (session, sd);
		do {
			ret = gnutls_handshake (session);
		}
		while (ret < 0 && gnutls_error_is_fatal (ret) == 0);

		if (ret < 0) {
			close (sd);
			gnutls_deinit (session);
			fprintf (stderr, "*** Handshake has failed (%s)\n\n", gnutls_strerror (ret));
			continue;
		}
		printf ("- Handshake was completed\n");

		ret = gnutls_certificate_verify_peers3 (session, NULL, &status);
		if (ret < 0) {
			fprintf (stderr, "Certificate verification has failed : %s\n", gnutls_strerror (ret));
			continue;
		}

		type = gnutls_certificate_type_get (session);
	        ret = gnutls_certificate_verification_status_print( status, type, &out, 0);
		if (ret < 0) {
			printf ("Error gcvsp\n");
			continue;
		}

		printf ("%s\n", out.data);
		gnutls_free(out.data);

		if (status != 0) /* Certificate is not trusted */
			continue;

		/* see the Getting peer's information example */
		/* print_info(session); */

		for (;;) {
			ret = gnutls_record_recv (session, buffer, MAX_BUF);

			if (ret == 0) {
				printf ("\n- Peer has closed the GnuTLS connection\n");
				break;
			} else if (ret < 0 && gnutls_error_is_fatal (ret) == 0) {
				fprintf (stderr, "*** Warning: %s\n", gnutls_strerror (ret));
			} else if (ret < 0) {
				fprintf (stderr, "\n*** Received corrupted data(%d). Closing the connection.\n\n", ret);
				break;
			} else if (ret > 0) {
				// echo data back to the client
				gnutls_record_send (session, buffer, ret);
			}
		}
		printf ("\n");
		// do not wait for the peer to close the connection.
		gnutls_bye (session, GNUTLS_SHUT_WR);

		close (sd);
		gnutls_deinit (session);

	}
	close (listen_sd);

	gnutls_certificate_free_credentials (xcred);
	gnutls_priority_deinit (priority_cache);

	gnutls_global_deinit ();

	return 0;
}

