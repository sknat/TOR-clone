
/*
	sclient - Sample SOCKv4 client for testing purposes
*/

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include "socksproto.h"
#include "config.h"


int main(int argc, char**argv)
{
	int socket_descriptor;
	int ret;
	struct sockaddr_in sockaddr_server;
	SOCKS4RequestHeader header;
	SOCKS4IP4RequestBody req;
	SOCKS4Response response;
	char username = '\0';
	char sendline[32]="GET / HTTP1.0\r\n\r\n";
	char buffer[SOCKS_BUFFER_SIZE+1];

	socket_descriptor = socket (AF_INET, SOCK_STREAM, 0);

	bzero (&sockaddr_server, sizeof(sockaddr_server));
	sockaddr_server.sin_family = AF_INET;
	sockaddr_server.sin_addr.s_addr = inet_addr(CLIENT_IP);
	sockaddr_server.sin_port = htons(CLIENT_PORT);

	ret = connect(socket_descriptor, (struct sockaddr *)&sockaddr_server, sizeof(sockaddr_server));
	if (ret != 0) {
		fprintf(stderr, "Err 50\n");
	}

	header.version = 4;
	header.cmd = CMD_CONNECT;

	if (send(socket_descriptor, (char*)&header, sizeof(SOCKS4RequestHeader), 0) != sizeof(SOCKS4RequestHeader)) {
		fprintf (stderr, "Err 100\n");
		return -1;
	}

	req.port = htons(TARGET_PORT);
	req.ip_dst = inet_addr(TARGET_IP);

	if(send(socket_descriptor, (char*)&req, sizeof(SOCKS4IP4RequestBody), 0) != sizeof(SOCKS4IP4RequestBody)) {
		fprintf (stderr, "Err 200\n");
		return -1;
	}

	if(send(socket_descriptor, &username, 1, 0) != 1) {
		fprintf (stderr, "Err 250\n");
		return -1;
	}

	if((ret = recv(socket_descriptor, (char*)&response, sizeof(SOCKS4Response), 0)) != sizeof(SOCKS4Response)) {
		fprintf (stderr, "Err 300 (%d)\n", ret);
		return -1;
	}

	if (response.status == RESP_SUCCEDED) {
		printf ("Success\n");
	} else {
		printf ("Error 400 : %d\n", response.status);
	}

	if(send(socket_descriptor, sendline, 17, 0) != 17) {
		fprintf (stderr, "Err 500\n");
		return -1;
	}

	for (;;) {
		if((ret = recv(socket_descriptor, buffer, SOCKS_BUFFER_SIZE, 0)) > 0) {
			buffer[ret] = '\0';
			printf ("Received a response ! (%d) : %s\n", ret, buffer);
		} else {
			break;
		}
	}

	close (socket_descriptor);
	return 0;
}

