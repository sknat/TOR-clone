
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "mytcp.h"

void *connect_to_host(uint32_t ip, uint16_t port) {
	struct sockaddr_in sockaddr_server;
	int socket_descriptor;
	int ret;

	socket_descriptor = socket (AF_INET, SOCK_STREAM, 0);

	bzero (&sockaddr_server, sizeof(sockaddr_server));
	sockaddr_server.sin_family = AF_INET;
	sockaddr_server.sin_addr.s_addr = ip;
	sockaddr_server.sin_port = htons(port);

	ret = connect(socket_descriptor, (struct sockaddr*)&sockaddr_server, sizeof(sockaddr_server));
	if (ret != 0) {
		printf ("Connection to target failed in function connect_to_host()\n");
		return NULL;
	}
	printf ("Connection to target succeded\n");

	return (void *)socket_descriptor;
}


