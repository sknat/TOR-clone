/*
	setdir - sets the list of trusted relays and stores it in a file
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../config.h"
#include "../lib/tcp.h"

int main() {
	unsigned int nbr, port;
	int i, ret;
	int file;
	char buffer[32];
	MYSOCKET *content;

	printf ("Number of relays > ");
	ret = scanf ("%u", &nbr);
	if (ret != 1) {
		fprintf (stderr, "Err 100 : %d\n", ret);
		return -1;
	}

	if (nbr > 10000) {
		fprintf (stderr, "Too much relays : %d\n", nbr);
		return -1;
	}

	content = (MYSOCKET *)malloc(sizeof(MYSOCKET)*nbr);

	for (i=0; i<nbr; i++) {
		printf ("Relay #%d's IP > ", i);
		ret = scanf ("%s", buffer);
		if (ret != 1) {
			fprintf (stderr, "Err 200 : %d\n", ret);
		}
		content[i].ip = inet_addr(buffer);
		
		printf ("Relay #%d's port > ", i);
		ret = scanf ("%u", &port);
		if (ret != 1) {
			fprintf (stderr, "Err 200 : %d\n", ret);
		}
		content[i].port = htons(port);
	}

	file = open (PATH_LIST_RELAYS, O_WRONLY | O_CREAT);
	if (file == -1) {
		fprintf (stderr, "Impossible to open \"%s\"\n", PATH_LIST_RELAYS);
		free (content);
		return -1;
	}

	ret = write (file, content, sizeof(MYSOCKET)*nbr);
	if (ret != sizeof(MYSOCKET)*nbr) {
		fprintf (stderr, "Error in writing : %d\n", ret);
		free (content);
		return -1;
	}
	close (file);

	free (content);
	printf ("List of trusted relays successfully written in file \"%s\"\n", PATH_LIST_RELAYS);
	return 0;
}
