#ifndef MY_TLS
#define MY_TLS

#include <gnutls/gnutls.h>
#include <netinet/in.h>

#define MAX_BUF 1024

extern gnutls_certificate_credentials_t xcred;


typedef struct PORC_STREAM {
	uint32_t ip;	// target ip
	uint16_t port;	// target port
	gnutls_session_t session;
	int socket_descriptor;
}	PORC_STREAM;


typedef struct PORC_HANDSHAKE_REQUEST {
	uint32_t ip;		// target IP
	uint16_t port;		// target port
} __attribute__((packed)) 	PORC_HANDSHAKE_REQUEST;


#define PORC_SUCCESS	0
#define PORC_ERROR	1

typedef struct PORC_HANDSHAKE_RESPONSE {
	uint8_t	status;
} __attribute__((packed)) 	PORC_HANDSHAKE_RESPONSE;


int mytls_client_global_init ();

int mytls_client_session_init (uint32_t ip, uint16_t port,
        gnutls_session_t *session, int *socket_descriptor);

void mytls_client_end (gnutls_session_t *session, int socket_descriptor);

int mytls_server_init (gnutls_certificate_credentials_t *xcred, gnutls_priority_t *priority_cache, int *listen_socket_descriptor,
	struct sockaddr_in *sockaddr_server);


#endif
