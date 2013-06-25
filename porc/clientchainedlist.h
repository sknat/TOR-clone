/*
	clientchainedlist - Chained lists for the PORC client.
*/

#ifndef PORC_CCL
#define PORC_CCL

#include "clientmain.h"


typedef struct CLIENT_CHAINED_LIST_ITEM
{
	int id;				// SOCKS session id
	int client_socket_descriptor;	// SOCKS client socket descriptor
	uint32_t ip;			// target ip
	uint16_t port;			// target port
} 	CLIENT_CHAINED_LIST_ITEM;

typedef struct CLIENT_CHAINED_LIST_LINK
{
	CLIENT_CHAINED_LIST_ITEM item;
	struct CLIENT_CHAINED_LIST_LINK *nxt;
} 	CLIENT_CHAINED_LIST_LINK;

typedef struct CLIENT_CHAINED_LIST
{
	int index;		// >= max(ids) + 1
	int length;
	CLIENT_CHAINED_LIST_LINK *first;
}	CLIENT_CHAINED_LIST;


extern CLIENT_CHAINED_LIST porc_sessions;



void ClientChainedListInit (CLIENT_CHAINED_LIST* p);

int ClientChainedListRemove (CLIENT_CHAINED_LIST* p, int id);

int ClientChainedListFind (CLIENT_CHAINED_LIST* p, int id, CLIENT_CHAINED_LIST_ITEM **item);

/*
	A new link is allocated and a pointer to its content is given.
*/
void ClientChainedListNew (CLIENT_CHAINED_LIST *p, CLIENT_CHAINED_LIST_ITEM **item);

void ClientChainedListClear (CLIENT_CHAINED_LIST *p);


#endif

