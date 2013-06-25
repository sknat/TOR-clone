#ifndef PORC_H
#define PORC_H

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "config.h"
#include "mytcp.h"
#include "mytls.h"
#include "clientmain.h"


extern int nbr_relays;
extern MYSOCKET *list_relays;



/*
	DIRECTORY_REQUEST - Request for the list of the trusted relays.
*/
#define DIRECTORY_ASK 65
typedef struct DIRECTORY_REQUEST {
	uint8_t command;
} __attribute__((packed))	DIRECTORY_REQUEST;

/*
	DIRECTORY_RESPONSE - Response from the directory to a DIRECTORY_REQUEST message.
*/
#define DIRECTORY_SUCCESS	0
#define DIRECTORY_FAILURE	1
typedef struct DIRECTORY_RESPONSE {
	uint8_t status;
	uint16_t nbr;		// number of MYSOCKET structures following
} __attribute__((packed))	DIRECTORY_RESPONSE;

///////commands for the end of the tunnel.

#define PORC_COMMAND_OPEN_SOCKS		100
#define PORC_COMMAND_OPEN_PORC 		101
#define PORC_COMMAND_CLOSE_SOCKS 	102
#define PORC_COMMAND_CLOSE_PORC		103
#define PORC_COMMAND_TRANSMIT		0

/*
	Porc Handshake for symmetric cryptography
*/
#define PUB_KEY_ASK 66
typedef struct PUB_KEY_REQUEST {
	uint8_t command;
} __attribute__((packed))	PUB_KEY_REQUEST;

#define PUB_KEY_SUCCESS 0
#define PUB_KEY_FAILURE 1
typedef struct PUB_KEY_RESPONSE {
	uint8_t status;
	char public_key[PUBLIC_KEY_LEN];
} __attribute__((packed))	PUB_KEY_RESPONSE;

#define CRYPT_SYM_KEY_SUCCESS 0
#define CRYPT_SYM_KEY_FAILURE 1
typedef struct CRYPT_SYM_KEY_RESPONSE {
	uint8_t status;
	char crypt_sym_key[CRYPT_SYM_KEY_LEN];
} __attribute__((packed)) CRYPT_SYM_KEY_RESPONSE;

/*
	gnutls_global_init must have been called prior to thiese functions
*/
extern int client_circuit_init ();
extern int client_circuit_free ();

#endif

