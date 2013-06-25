/*
	relaychainedlist - Chained lists for the PORC relay.
*/

#ifndef PORC_RCL
#define PORC_RCL

#include "relaymain.h"


typedef struct ITEM_RELAY
{
	int id;				// local PORC peer id
	int socket_descriptor;
	gnutls_t session;
} 	ITEM_CLIENT;

typedef struct ITEM_TARGET
{
	int id;				// local PORC target id
	int id_session;			// local PORC session id associated with the target
	int socket_descriptor;
} 	ITEM_SERVER;

typedef struct ITEM_SESSION
{
	int id;				// local PORC session id
	int type;			// socket type : SOCKET_INRELAY for an client relay,
					//	SOCKET_OUTRELAY for a server relay, SOCKET_TARGET for a extern target
	int socket_descriptor;
	gnutls_t session;
	int prev_id;			// previous relay's PORC session id if type = SOCKET_OUTRELAY or SOCKET_TARGET
} 	ITEM_TARGET;

typedef struct CHAINED_LIST_LINK
{
	void *item;
	struct CHAINED_LIST_LINK *nxt;
} 	CHAINED_LIST_LINK;

typedef struct CHAINED_LIST
{
	int index;		// >= max(ids) + 1
	int length;
	CLIENT_CHAINED_LIST_LINK *first;
}	CLIENT_CHAINED_LIST;


extern CHAINED_LIST client_porc_sessions;
extern CHAINED_LIST target_porc_sessions;
extern CHAINED_LIST server_porc_sessions;


void ChainedListInit (CHAINED_LIST* p);

int ChainedListRemove (CHAINED_LIST* p, int id);

int ChainedListFind (CHAINED_LIST* p, int id, void **item);

/*
	A new link is allocated and a pointer to its content is given.
*/
void ChainedListNew (CHAINED_LIST *p, void **item, int item_size);

void ChainedListClear (CHAINED_LIST *p);


#endif

