#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <pthread.h>

#include "socks.h"

int client_count = 0, max_clients = 10;


int create_listen_socket() {
	int server_socket_descriptor;
	struct sockaddr_in sockaddr_server;

	if ((server_socket_descriptor = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		fprintf (stderr, "[-] Could not create socket.\n");
		return -1;
	}

	bzero(&sockaddr_server, sizeof(sockaddr_server));
	sockaddr_server.sin_family = AF_INET;
	sockaddr_server.sin_addr.s_addr = htonl(INADDR_ANY);
	sockaddr_server.sin_port = htons(PROXY_PORT);

	if (bind(server_socket_descriptor, (struct sockaddr *) &sockaddr_server, sizeof(sockaddr_server)) < 0) {
		fprintf (stderr, "[-] Bind error.\n");
		return -1;
	}

	if (listen(server_socket_descriptor, MAXPENDING) < 0) {
		fprintf (stderr, "[-] Listen error.\n");
		return -1;
	}
	return server_socket_descriptor;
}


int connect_to_host(uint32_t ip, uint16_t port) {
	struct sockaddr_in sockaddr_server;
	int socket_descriptor;
	char buffer[32];
	int ret;

	socket_descriptor = socket (AF_INET, SOCK_STREAM, 0);

	bzero (&sockaddr_server, sizeof(sockaddr_server));
	sockaddr_server.sin_family = AF_INET;
	sockaddr_server.sin_addr.s_addr = ip;
	sockaddr_server.sin_port = htons(port);

	ret = connect(socket_descriptor, (struct sockaddr*)&sockaddr_server, sizeof(sockaddr_server));
	if (ret != 0) {
		printf ("Connection to target failed in function connect_to_host()\n");
		return -1;
	}
	printf ("Connection to target succeded\n");

	return socket_descriptor;
}

void set_fds(int fd1, int fd2, fd_set *fds) {
	FD_ZERO (fds);
	FD_SET (fd1, fds);
	FD_SET (fd2, fds);
}

void do_proxy(int fd1, int fd2, char *buffer) {
	fd_set read_fds;
	int result;
	int nfds = fd1+1;
	if (fd2>fd1) {
		nfds = fd2+1;
	}

	set_fds(fd1, fd2, &read_fds);
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
		set_fds(fd1, fd2, &read_fds);
	}
}


int handle_request(int client_socket_descriptor, char *buffer) {
	SOCKS4RequestHeader header;
	SOCKS4IP4RequestBody req;
	SOCKS4Response response;
	int totarget_socket_descriptor = -1;
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

	totarget_socket_descriptor = connect_to_host(req.ip_dst, ntohs(req.port));
	if(totarget_socket_descriptor == -1) {
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

	do_proxy(totarget_socket_descriptor, client_socket_descriptor, buffer);
	close (totarget_socket_descriptor);

	return 0;
}

void *handle_connection(void *arg) {
	int client_socket_descriptor = (int)arg;
	char *buffer;

	buffer = (char *)malloc(BUF_SIZE);

	handle_request(client_socket_descriptor, buffer);

	printf ("Closing client %d\n", client_socket_descriptor);
	close (client_socket_descriptor);
	free (buffer);
	client_count--;
	return 0;
}

int main(int argc, char *argv[]) {
	struct sockaddr_in sockaddr_client;
	int listen_socket_descriptor;
	int client_socket_descriptor;
	unsigned int length = sizeof(sockaddr_client);

	listen_socket_descriptor = create_listen_socket();
	if(listen_socket_descriptor == -1) {
		fprintf (stderr, "Failed to create server\n");
		return 1;
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
}


