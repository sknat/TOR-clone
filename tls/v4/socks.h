#ifndef MYSOCKS
#define MYSOCKS

#include "config.h"
#include "mytcp.h"

/*
	do_proxy is responsible for stream2 desallocation.
*/
extern void (*do_proxy) (int client_socket_descriptor, void *stream2);
extern void *(*new_client) (uint32_t ip, uint16_t port);
int proxy_socksv4 (int port);



#endif

