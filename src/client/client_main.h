/* ################################################################################
							Client - PORC client

	The PORC client transfers a socks stream to a PORC circuit to the target.

   ################################################################################*/

#ifndef PORC_CLIENT_MAIN
#define PORC_CLIENT_MAIN

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <gcrypt.h>

#include "../lib/tcp.h"
#include "../lib/tls.h"
#include "../lib/chained_list.h"
#include "../lib/signaling.h"
#include "../lib/porc_protocol.h"

#include "../config.h"

#include "socks.h"
#include "select.h"

extern CHAINED_LIST socks_session_list;

/*
	CLIENT_CIRCUIT - Circuit information for the PORC client.
*/
typedef struct CLIENT_CIRCUIT {
	gnutls_session_t relay1_gnutls_session;
	int relay1_socket_descriptor;
	gcry_cipher_hd_t gcry_cipher_hd[MAX_CIRCUIT_LENGTH];
	int length;
}	CLIENT_CIRCUIT;


extern CLIENT_CIRCUIT client_circuit;



extern pthread_t accepting_thread;
extern pthread_t selecting_thread;



void signal_handler_interrupt (int);
void signal_handler_newstream (int);

extern int client_circuit_init (int circuit_length);
extern int client_circuit_free ();

extern int client_porc_send (PORC_COMMAND command, char *payload, size_t payload_length);
extern int client_porc_recv (PORC_RESPONSE *porc_response, char **payload, size_t *payload_length);
extern int set_symmetric_key (char **key_crypted, int *key_crypted_length, char *public_key, int public_key_length, 
int relay_index);


#endif
