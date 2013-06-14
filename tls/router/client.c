#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include "utils.h"
#include "config.h"

#define MAX_BUF 1024
#define MSG "blablabla"

extern int tcp_connect (void);
extern void tcp_close (int sd);
static int _verify_certificate_callback (gnutls_session_t session);

int main (void) {
	int ret, sd, ii;
	gnutls_session_t session;
	char buffer[MAX_BUF + 1];
	const char *err;
	gnutls_certificate_credentials_t xcred;

	if ((ret=gnutls_global_init ())<0) {
		printf ("Error in gnutls_global_init : %s\n", gnutls_strerror(ret));
	}

	if ((ret=gnutls_certificate_allocate_credentials (&xcred))<0) {
		printf ("Error in gnutls_certificate_allocate_credentials : %s\n", gnutls_strerror(ret));
	}

	// sets the trusted cas file
	if ((ret=gnutls_certificate_set_x509_trust_file (xcred, ROOT_CA_FILE, GNUTLS_X509_FMT_PEM))<0) {
		printf ("Error in gnutls_certificate_set_x509_trust_file : %s\n", gnutls_strerror(ret));
	}
	gnutls_certificate_set_verify_function (xcred, _verify_certificate_callback);

	// If client holds a certificate it can be set using the following:
	gnutls_certificate_set_x509_key_file (xcred,
		CLIENT_CERT_FILE, CLIENT_KEY_FILE, GNUTLS_X509_FMT_PEM);

	// Initialize TLS session
	gnutls_init (&session, GNUTLS_CLIENT);

	gnutls_session_set_ptr (session, (void *) "my_host_name");

	gnutls_server_name_set (session, GNUTLS_NAME_DNS, "my_host_name", 
		strlen("my_host_name"));

	/* Use default priorities */
	ret = gnutls_priority_set_direct (session, "NORMAL", &err);
	if (ret < 0) {
		if (ret == GNUTLS_E_INVALID_REQUEST) {
			fprintf (stderr, "Syntax error at: %s\n", err);
		}
		exit (1);
	}

	// put the x509 credentials to the current session
	gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

	// connect to the peer
	sd = tcp_connect ();

	gnutls_transport_set_int (session, sd);
	gnutls_handshake_set_timeout (session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	// Perform the TLS handshake
	do {
		ret = gnutls_handshake (session);
	} while (ret < 0 && gnutls_error_is_fatal (ret) == 0);

	if (ret < 0) {
		fprintf (stderr, "*** Handshake failed\n");
		gnutls_perror (ret);
	goto end;
	} else {
		char* desc;

//      desc = gnutls_session_get_desc(session);
//      printf ("- Session info: %s\n", desc);
		gnutls_free(desc);
	}

	gnutls_record_send (session, MSG, strlen (MSG));

	ret = gnutls_record_recv (session, buffer, MAX_BUF);
	if (ret == 0) {
		printf ("- Peer has closed the TLS connection\n");
		goto end;
	} else if (ret < 0 && gnutls_error_is_fatal (ret) == 0) {
		fprintf (stderr, "*** Warning: %s\n", gnutls_strerror (ret));
	} else if (ret < 0) {
		fprintf (stderr, "*** Error: %s\n", gnutls_strerror (ret));
		goto end;
	}

	if (ret > 0) {
		printf ("- Received %d bytes: ", ret);
		for (ii = 0; ii < ret; ii++) {
			fputc (buffer[ii], stdout);
		}
		fputs ("\n", stdout);
	}

	gnutls_bye (session, GNUTLS_SHUT_RDWR);

end:

	tcp_close (sd);

	gnutls_deinit (session);

	gnutls_certificate_free_credentials (xcred);

	gnutls_global_deinit ();

	return 0;
}

/*
	This function will verify the peer's certificate, and check
	if the hostname matches, as well as the activation, expiration dates.
 */
static int _verify_certificate_callback (gnutls_session_t session) {
	unsigned int status;
	int ret, type;
	const char *hostname;
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

	printf ("%s", out.data);

	gnutls_free(out.data);

	if (status != 0) /* Certificate is not trusted */
		return GNUTLS_E_CERTIFICATE_ERROR;

	// notify gnutls to continue handshake normally
	return 0;
}