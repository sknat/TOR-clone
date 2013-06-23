/*
	clientchainedlist - Chained lists for the PORC client.
*/

#include <stdlib.h>
#include <stdio.h>

typedef struct CLIENT_CHAINED_LIST_ITEM
{
	int client_socket_descriptor;	// SOCKS client socket descriptor
	int id;				// Connection id
} 	CLIENT_CHAINED_LIST_ITEM;


void ClientChaineListInit (CLIENT_CHAINED_LIST* p, int id);

int ClientChaineListDelete (CLIENT_CHAINED_LIST* p, int id);

int ClientChaineListFind (CLIENT_CHAINED_LIST* p, int id, CLIENT_CHAINED_LIST_ITEM *item);

void ClientChaineListPush (CLIENT_CHAINED_LIST *p, CLIENT_CHAINED_LIST_ITEM *item);

void ClientChaineListClear (CLIENT_CHAINED_LIST *p);

