/*
	socks - SOCKSv4 module
*/

#ifndef MYSOCKS
#define MYSOCKS

#include "config.h"
#include "mytcp.h"

/*
	new_client - Initialize the connection. This function is called once during the SOCKSv4 handshake.

	client_socket_descriptor - SOCKS client socket descriptor
	ip - target ip
	port - target port

	This function returns 0 in case of success and -1 otherwise.

	Note - By default, the new_client function acts as a normal SOCKSv4 proxy would do. This pointer can be changed to allow
		additionnal processing (eg setting up an encrypted connection)
*/
extern int (*new_client) (int client_socket_descriptor, uint32_t ip, uint16_t port);

/*
	proxy_socksv4 - Starts a SOCKSv4 proxy that sets up connections.

	When a new client comes, proxy_socksv4 calls new_client() to initialize the connection. Then another thread must process
		the new connection.
*/
int proxy_socksv4 (int port);



#endif

