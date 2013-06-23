/*
	mytls - gnutls encapsulation for the PORC project.
*/

#ifndef MY_TLS
#define MY_TLS

#include <gnutls/gnutls.h>
#include <netinet/in.h>

#define MAX_BUF 1024

/*
	xcred : global credentials structure.

	BUG : relay cannot use this variable.
*/
extern gnutls_certificate_credentials_t xcred;

/*
	PORC_STREAM - Temporary, a better connection handling system to be found.
*/
typedef struct PORC_STREAM {
	uint32_t ip;	// target ip
	uint16_t port;	// target port
	gnutls_session_t session;
	int socket_descriptor;
}	PORC_STREAM;

/*
	PORC_HANDSHAKE_REQUEST - Request sent by the PORC client at the beginning of the TLS connection.
*/
typedef struct PORC_HANDSHAKE_REQUEST {
	uint32_t ip;		// target IP
	uint16_t port;		// target port
} __attribute__((packed)) 	PORC_HANDSHAKE_REQUEST;


/*
	 PORC_HANDSHAKE_RESPONSE - Response from the PORC relay to the PORC client.
*/
#define PORC_SUCCESS	0
#define PORC_ERROR	1
typedef struct PORC_HANDSHAKE_RESPONSE {
	uint8_t	status;
} __attribute__((packed)) 	PORC_HANDSHAKE_RESPONSE;

/*
	mytls_client_global_init - Global initialization of the mytls library, for the PORC client.

	Returns 0 on success, -1 otherwise.
*/
int mytls_client_global_init ();

/*
	mytls_client_session_init - Initialization of a TLS connection, for a client.

	ip - relay IP
	port - relat port
	session - a pointer to the new gnutls session handler
	socket_descriptor - a pointer to the new socket descriptor

	Returns 0 on success, -1 otherwise.

	Note : Both the gnutls session handler and the socket descriptor are needed to hold a TLS connection. 
*/
int mytls_client_session_init (uint32_t ip, uint16_t port,
        gnutls_session_t *session, int *socket_descriptor);


/*
	mytls_server_init - Starts listening, for a PORC relay.


	listen_socket_descriptor - a pointer to the new socket descriptor
	sockaddr_server - tells on which port the server should listen

	Returns 0 on success, -1 otherwise.

*/
int mytls_server_init (gnutls_certificate_credentials_t *xcred, gnutls_priority_t *priority_cache, int *listen_socket_descriptor,
	struct sockaddr_in *sockaddr_server);


#endif
