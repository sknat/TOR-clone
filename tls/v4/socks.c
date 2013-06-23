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
	Default values for do_proxy and new_client.
*/
void (*do_proxy) (int client_socket_descriptor, void *stream2) = &do_proxy_id;
void *(*new_client) (uint32_t ip, uint16_t port) = &connect_to_host;

int client_count = 0;
int max_clients = 10;


void do_proxy_id(int client_socket_descriptor, void *stream2) {
	int fd1 = client_socket_descriptor;
	int fd2 = (int)stream2;
	fd_set read_fds;
	int result;
	int nfds = fd1+1;
	char buffer[BUF_SIZE+1];

	if (fd2>fd1) {
		nfds = fd2+1;
	}

	FD_ZERO (&read_fds);
	FD_SET (fd1, &read_fds);
	FD_SET (fd2, &read_fds);

	while((result = select(nfds, &read_fds, 0, 0, 0)) > 0) {
		if (FD_ISSET (fd1, &read_fds)) {
			int recvd = recv(fd1, buffer, BUF_SIZE, 0);
			if(recvd <= 0)
				return;
			send(fd2, buffer, recvd, 0);
		}
		if (FD_ISSET (fd2, &read_fds)) {
			int recvd = recv(fd2, buffer, BUF_SIZE, 0);
			if(recvd <= 0)
				return;
			send(fd1, buffer, recvd, 0);
		}

		FD_ZERO (&read_fds);
		FD_SET (fd1, &read_fds);
		FD_SET (fd2, &read_fds);
	}

	close (fd2);
}


int handle_request(int client_socket_descriptor) {
	SOCKS4RequestHeader header;
	SOCKS4IP4RequestBody req;
	SOCKS4Response response;
	void *target;
	int ret;

	recv(client_socket_descriptor, (char*)&header, sizeof(SOCKS4RequestHeader), 0);
	if(header.version != 4 || header.cmd != CMD_CONNECT) {
		fprintf (stderr, "Incorrect header.\n");
		return -1;}
	if(recv(client_socket_descriptor, (char*)&req, sizeof(SOCKS4IP4RequestBody), 0) != sizeof(SOCKS4IP4RequestBody)) {
		fprintf (stderr, "Error in request reception.\n");
		return -1;}
	char c=' ';
	while(c!='\0') {
		if(recv(client_socket_descriptor, &c, 1, 0) != 1) {
			fprintf (stderr, "Error in username reception.\n");
			return -1;}
	}

	target = (* new_client) (req.ip_dst, ntohs(req.port));
	if(target == NULL) {
		fprintf (stderr, "Failed to connect to target.\n");
		return -1;
	}

	response.null_byte=0;
	response.status=RESP_SUCCEDED;
	response.rsv1=0;
	response.rsv2=0;
	ret = send(client_socket_descriptor, (const char*)&response, sizeof(SOCKS4Response), 0);
	if (ret != sizeof(SOCKS4Response)) {
		fprintf (stderr, "Error in response (%d)\n", ret);
		return -1;
	}

	(*do_proxy) (client_socket_descriptor, target);

	return 0;
}

void *handle_connection(void *arg) {
	int client_socket_descriptor = (int)arg;

	handle_request(client_socket_descriptor);

	printf ("Closing client %d\n", client_socket_descriptor);
	close (client_socket_descriptor);
	client_count--;
	return 0;
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
			client_count++;
			pthread_create(&thread, &attr, handle_connection, (void*)client_socket_descriptor);
		}
	}

	return 0;
}


