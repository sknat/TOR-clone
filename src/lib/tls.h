/* ################################################################################
					
					TLS Utility library for the Porc protocol
							(gnutls encapsulation)
					
   ################################################################################*/
#ifndef MY_TLS
#define MY_TLS

#include <gnutls/gnutls.h>
#include <netinet/in.h>

#include "../config.h"

/*
	xcred : global credentials structure.
*/
extern gnutls_certificate_credentials_t xcred;



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


	listen_socket_descriptor : a pointer to the new socket descriptor
	sockaddr_server : tells on which port the server should listen
	trust : 1 if needed to load the root certificate, 0 otherwise

	Returns 0 on success, -1 otherwise.

*/
int mytls_server_init (int port, gnutls_certificate_credentials_t *xcred, gnutls_priority_t *priority_cache, int *listen_socket_descriptor,
	struct sockaddr_in *sockaddr_server, int trust);


#endif
