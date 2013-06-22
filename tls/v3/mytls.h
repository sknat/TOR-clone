#ifndef MY_TLS
#define MY_TLS

#include <gnutls/gnutls.h>
#include <netinet/in.h>

#define MAX_BUF 1024


int mytls_client_global_init (gnutls_certificate_credentials_t *xcred);

int mytls_client_session_init (gnutls_certificate_credentials_t *xcred,
        gnutls_session_t *session, int *socket_descriptor);

void mytls_client_end (gnutls_certificate_credentials_t *xcred,
        gnutls_session_t *session, int socket_descriptor);

int mytls_server_init (gnutls_certificate_credentials_t *xcred, gnutls_priority_t *priority_cache, int *listen_socket_descriptor,
	struct sockaddr_in *sockaddr_server);


#endif
