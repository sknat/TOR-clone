#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include "config.h"


// tcp.c
int tcp_connect (void);
void tcp_close (int sd);

/*
	Connects to the peer and returns a socket descriptor.
*/
extern int tcp_connect (void) {
	int err, sd;
	struct sockaddr_in sa;

	sd = socket (AF_INET, SOCK_STREAM, 0);

	memset (&sa, '\0', sizeof (sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons (SERV_PORT);
	inet_pton (AF_INET, SERV_IP, &sa.sin_addr);

	err = connect (sd, (struct sockaddr *) & sa, sizeof (sa));
	if (err < 0) {
		fprintf (stderr, "tcp_connect : Connect error\n");
		exit (1);
	}

	return sd;
}

// Closes the given socket descriptor.
extern void tcp_close (int sd) {
	shutdown (sd, SHUT_RDWR);     /* no more receptions */
	close (sd);
}
