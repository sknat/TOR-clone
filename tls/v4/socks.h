/*
	socks - SOCKSv4 module
*/

#ifndef MYSOCKS
#define MYSOCKS

#include "config.h"
#include "mytcp.h"

/*
	new_client - Initialize the connection. This function is called once during the SOCKSv4 handshake.

	ip - target ip
	port - target port

	This function returns NULL in case of error. Otherwise, the return value will by passed to do_proxy as the parameter stream_2.

	Note - By default, the new_client function acts as a normal SOCKSv4 proxy would do. This pointer can be changed to allow
		additionnal processing (eg encryption)
*/
extern void *(*new_client) (uint32_t ip, uint16_t port);

/*
	do_proxy - Do proxy between the SOCKS client and a server.

	client_socket_descriptor - SOCKS client socket descriptor
	stream2 - Value returned by new_client().

	do_proxy is responsible for stream2 desallocation.

	Note - By default, the do_proxy function acts as a normal SOCKSv4 proxy would do. This pointer can be changed to allow
		additionnal processing (eg encryption)
*/
extern void (*do_proxy) (int client_socket_descriptor, void *stream2);

/*
	proxy_socksv4 - Starts a SOCKSv4 proxy.

	When a new client comes, proxy_socksv4 calls new_client() to initialize the connection, and then do_proxy().
*/
int proxy_socksv4 (int port);



#endif

