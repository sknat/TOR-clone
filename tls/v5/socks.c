#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "socksproto.h"
#include "socks.h"

void do_proxy_id(int client_socket_descriptor, void *stream2);

/*
	Default value for new_client.
*/
int (*new_client) (int client_socket_descriptor, uint32_t ip, uint16_t port) = &connect_to_host;



void *handle_connection(void *arg) {
	int client_socket_descriptor = (int)arg;
	SOCKS4RequestHeader header;
	SOCKS4IP4RequestBody req;
	SOCKS4Response response;
	int ret;

	recv(client_socket_descriptor, (char*)&header, sizeof(SOCKS4RequestHeader), 0);
	if(header.version != 4 || header.cmd != CMD_CONNECT) {
		fprintf (stderr, "Incorrect header.\n");
		return;}
	if(recv(client_socket_descriptor, (char*)&req, sizeof(SOCKS4IP4RequestBody), 0) != sizeof(SOCKS4IP4RequestBody)) {
		fprintf (stderr, "Error in request reception.\n");
		return;}
	char c=' ';
	while(c!='\0') {
		if(recv(client_socket_descriptor, &c, 1, 0) != 1) {
			fprintf (stderr, "Error in username reception.\n");
			return;}
	}

	ret = (* new_client) (client_socket_descriptor, req.ip_dst, ntohs(req.port));
	if(ret != 0) {
		fprintf (stderr, "Failed to connect to target.\n");
		return;
	}

	response.null_byte=0;
	response.status=RESP_SUCCEDED;
	response.rsv1=0;
	response.rsv2=0;
	ret = send(client_socket_descriptor, (const char*)&response, sizeof(SOCKS4Response), 0);
	if (ret != sizeof(SOCKS4Response)) {
		fprintf (stderr, "Error in response (%d)\n", ret);
		return;
	}

	return;
}

int proxy_socksv4 (int port) {
	struct sockaddr_in sockaddr_client;
	int listen_socket_descriptor;
	int client_socket_descriptor;
	unsigned int length = sizeof(sockaddr_client);

	listen_socket_descriptor = create_listen_socket(port);
	if(listen_socket_descriptor == -1) {
		fprintf (stderr, "Failed to create server\n");
		return -1;
	}
	printf ("Listening\n");

	pthread_t thread;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	for (;;) {
		while(client_count >= max_clients) {
			fprintf (stderr, "Warning - Too much client, waits 1s\n");
			sleep(1);
		}
		if ((client_socket_descriptor = accept(listen_socket_descriptor, (struct sockaddr *) &sockaddr_client, &length)) > 0) {
			printf ("New client %d\n", client_socket_descriptor);
			pthread_create(&thread, &attr, handle_connection, (void*)client_socket_descriptor);
		}
	}

	return 0;
}


