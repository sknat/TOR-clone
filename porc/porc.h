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


///////////////////////// Directory protocol


/*
	DIRECTORY_REQUEST - Request for the list of the trusted relays.
*/
#define DIRECTORY_ASK 65
typedef struct {
	uint8_t command;
} __attribute__((packed))	DIRECTORY_REQUEST;

/*
	DIRECTORY_RESPONSE - Response from the directory to a DIRECTORY_REQUEST message.
*/
#define DIRECTORY_SUCCESS	0
#define DIRECTORY_FAILURE	1
typedef struct {
	uint8_t status;
	uint16_t nbr;		// number of MYSOCKET structures following
} __attribute__((packed))	DIRECTORY_RESPONSE;


///////////////////////// PORC protocol

#define PORC_STATUS_SUCCESS 0		
#define PORC_STATUS_FAILURE 1

#define PORC_DIRECTION_DOWN 3
#define PORC_DIRECTION_UP 2

typedef struct
	uint32_t length;			// length of the whole packet
	PORC_COMMAND command;
	uint8_t direction;
	uint32_t porc_session_id;
} __attribute__((packed))	PORC_PACKET_HEADER;


//commands for the end of the tunnel.
typedef uint16_t PORC_COMMAND;
typedef uint16_t PORC_RESPONSE;

#define PORC_COMMAND_OPEN_SOCKS		100
typedef struct {
	uint32_t ip;
	uint16_t port;
	uint32_t socks_session_id;
} __attribute__((packed))	PORC_COMMAND_OPEN_SOCKS_CONTENT;

#define PORC_RESPONSE_OPEN_SOCKS	200
typedef struct {
	uint8_t status;
	uint32_t socks_session_id;
} __attribute__((packed))	PORC_RESPONSE_OPEN_SOCKS_CONTENT;
	
#define PORC_COMMAND_ASK_KEY 		101		// Ask public key to a relay
typedef struct {
	uint32_t ip;
	uint16_t port;
} __attribute__((packed))	PORC_COMMAND_ASK_KEY_CONTENT;

#define PORC_RESPONSE_ASK_KEY 		201
typedef struct {
	uint8_t status;
	uint32_t ip;
	uint16_t port;
	// public key following
} __attribute__((packed))	PORC_RESPONSE_ASK_KEY_CONTENT;

#define PORC_COMMAND_OPEN_PORC		102		// Send sym key crypted by public key to open a new PORC connection
typedef struct {
	uint32_t ip;
	uint16_t port;
	// crypted key + init vector follow
} __attribute__((packed))	PORC_CONTENT_OPEN_PORC_HEADER;

#define PORC_RESPONSE_OPEN_PORC		202		// Send sym key crypted by public key to open a new PORC connection
typedef struct {
	uint8_t status;
} __attribute__((packed))	PORC_CONTENT_OPEN_PORC;

#define PORC_COMMAND_CLOSE_SOCKS 	103
typedef struct {
	uint32_t socks_session_id;
} __attribute__((packed))	PORC_RESPONSE_OPEN_SOCKS_CONTENT;

#define PORC_RESPONSE_CLOSE_SOCKS 	203
typedef struct {
	uint32_t socks_session_id;
} __attribute__((packed))	PORC_RESPONSE_OPEN_SOCKS_CONTENT;

#define PORC_COMMAND_CLOSE_PORC		104

#define PORC_RESPONSE_CLOSE_PORC	204

#define PORC_COMMAND_TRANSMIT		105
typedef struct {
	uint32_t socks_session_id;
	// content following
} __attribute__((packed))	PORC_CONTENT_TRANSMIT;




///////////////////////// PORC handshake (between last relay and next relay)

#define PORC_HANDSHAKE_REQUEST_CODE	66
typedef struct {
	uint8_t command;
} __attribute__((packed))	PORC_HANDSHAKE_REQUEST;

typedef struct {
	uint8_t status;
	uint16_t key_length;		// key_length bytes following if status = PORC_HANDSHAKE_SUCCESS
} __attribute__((packed))	PORC_HANDSHAKE_KEY_HEADER;

#define PORC_HANDSHAKE_NEW_CODE	67
typedef struct {
	uint8_t command;
	uint32_t porc_session_id;	
	uint16_t key_length;		// crypted symmetric key + init vector bytes following
} __attribute__((packed))	PORC_HANDSHAKE_NEW;

typedef struct {
	uint8_t status;
} __attribute__((packed))	PORC_HANDSHAKE_ACK;




/*
	gnutls_global_init must have been called prior to thiese functions
*/
extern int client_circuit_init (int circuit_length);
extern int client_circuit_free ();

#endif

