#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "mytls.h"

#define MSG "blablabla"

int main (void) {
	int ret, i;
	int socket_descriptor;
	gnutls_session_t session;
	gnutls_certificate_credentials_t xcred;
	char buffer[MAX_BUF + 1];
	const char *err;

	if ((ret=mytls_client_global_init (&xcred))<0) {
		printf ("Error in mytls_client_global_init()\n");
	}

	if ((ret=mytls_client_session_init (&xcred, &session, &socket_descriptor))<0) {
		printf ("Error in mytls_client_global_init()\n");
	}

	gnutls_record_send (session, MSG, strlen (MSG));

	ret = gnutls_record_recv (session, buffer, MAX_BUF);
	if (ret == 0) {
		printf ("- Peer has closed the TLS connection\n");
		mytls_client_end(&xcred, &session, socket_descriptor);
		return -1;
	} else if (ret < 0 && gnutls_error_is_fatal (ret) == 0) {
		fprintf (stderr, "*** Warning: %s\n", gnutls_strerror (ret));
	} else if (ret < 0) {
		fprintf (stderr, "*** Error: %s\n", gnutls_strerror (ret));
		mytls_client_end(&xcred, &session, socket_descriptor);
		return -1;
	}

	if (ret > 0) {
		printf ("- Received %d bytes: ", ret);
		for (i = 0; i < ret; i++) {
			fputc (buffer[i], stdout);
		}
		fputs ("\n", stdout);
	}

	gnutls_bye (session, GNUTLS_SHUT_RDWR);
	mytls_client_end(&xcred, &session, socket_descriptor);

	return 0;
}
