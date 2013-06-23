/*
	clientchainedlist - Chained lists for the PORC client.
*/

#include <stdlib.h>
#include <stdio.h>

typedef struct RELAY_CHAINED_LIST_ITEM
{
	int id;				// Connection id
	int client_socket_descriptor;	// SPORC relay or client socket descriptor
	gnutls_t client_session;	// SPORC relay or client gnutls session
	int relay;			// 1 : the server is a PORC relay; 0 : it is not
	int server_socket_descriptor;	// server socket descriptor
	gnutls_t server_session;	// server gnutls session (if it is a PORC relay)
} 	RELAY_CHAINED_LIST_ITEM

void RelayChaineListInit (RELAY_CHAINED_LIST* p, int id);

int RelayChaineListDelete (RELAY_CHAINED_LIST* p, int id);

int RelayChaineListFind (RELAY_CHAINED_LIST* p, int id, RELAY_CHAINED_LIST_ITEM *item);

void RelayChaineListPush (RELAY_CHAINED_LIST *p, RELAY_CHAINED_LIST_ITEM *item);

void RelayChaineListClear (RELAY_CHAINED_LIST *p);

