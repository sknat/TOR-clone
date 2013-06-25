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
	DIRECTORY_REQUEST - Request for the list of the trusted relays.
*/
#define DIRECTORY_ASK	65
typedef struct DIRECTORY_REQUEST {
	uint8_t command;
} __attribute__((packed))	DIRECTORY_REQUEST;

/*
	DIRECTORY_RESPONSE - Response from the directory to a DIRECTORY_REQUEST message.
*/
#define DIRECTORY_SUCCESS	0
#define DIRECTORY_FAILURE	1
typedef struct DIRECTORY_RESPONSE {
	uint8_t status;
	uint16_t nbr;		// number of MYSOCKET structures following
} __attribute__((packed))	DIRECTORY_RESPONSE;


#define PORC_COMMAND_CONNECT_RELAY	100	// Asks the last PORC relay to join a new relay
#define PORC_COMMAND_CONNECT_TARGET	110	// Asks the last PORC relay to join a extern target
#define PORC_COMMAND_TRANFER		120	// Asks the PORC relays to transfer a message to the target
#define PORC_COMMAND_DISCONNECT		130	// Asks the last PORC relay to disconnect
#define PORC_COMMAND_DISCONNECT_TARGET	140	// Asks the last PORC relay to disconnect from the target
typedef uint8_t PORC_COMMAND;
#define PORC_ACK_CONNECT_RELAY		200	// Asks the last PORC relay to join a new relay
#define PORC_ACK_CONNECT_TARGET		210	// Asks the last PORC relay to join a extern target
typedef uint8_t PORC_ACK;

/*
	PORC_STREAM - Temporary, a better connection handling system to be found.
*
typedef struct PORC_STREAM {
	uint32_t ip;	// target ip
	uint16_t port;	// target port
	gnutls_session_t session;
	int socket_descriptor;
} __attribute__((packed))	PORC_STREAM;


	PORC_HANDSHAKE_REQUEST - Request sent by the PORC client at the beginning of the TLS connection.
*
typedef struct PORC_HANDSHAKE_REQUEST {
	uint32_t ip;		// target IP
	uint16_t port;		// target port
} __attribute__((packed)) 	PORC_HANDSHAKE_REQUEST;



	 PORC_HANDSHAKE_RESPONSE - Response from the PORC relay to the PORC client.
*
#define PORC_SUCCESS	0
#define PORC_ERROR	1
typedef struct PORC_HANDSHAKE_RESPONSE {
	uint8_t	status;
} __attribute__((packed)) 	PORC_HANDSHAKE_RESPONSE;*/


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
int mytls_server_init (int port, gnutls_certificate_credentials_t *xcred, gnutls_priority_t *priority_cache, int *listen_socket_descriptor,
	struct sockaddr_in *sockaddr_server);


#endif
