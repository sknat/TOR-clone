/*
	chainedlist - Chained lists for the PORC project.
*/

#ifndef PORC_CHAINED_LIST
#define PORC_CHAINED_LIST

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdlib.h>


typedef struct ITEM_CLIENT
{
	int id;				// SOCKS session id
	int client_socket_descriptor;	// SOCKS client socket descriptor
} 	ITEM_CLIENT;



// id is the local TLS session id
typedef struct ITEM_TLS_SESSION
{	
	int socket_descriptor;
	gnutls_session_t session;
}	ITEM_TLS_SESSION;


// id is the local PORC peer id for the PORC connection
typedef struct ITEM_PORC_SESSION
{
	int id_prev;			// PORC client peer's id for the PORC session
	// TODO keys
	ITEM_TLS_SESSION *client_tls_session;
	ITEM_TLS_SESSION *server_tls_session;
} 	ITEM_PORC_SESSION;


// id is the local SOCKS session id
typedef struct ITEM_SOCKS_SESSION
{
	int id_prev;			// PORC client's id for the SOCKS session
	int socks_session;		
	int target_socket_descriptor;
	int id_porc_session;		// local PORC session driving the SOCKS session
} 	ITEM_SOCKS_SESSION;




typedef struct CHAINED_LIST_LINK
{
	int id;
	void *item;
	struct CHAINED_LIST_LINK *nxt;
} 	CHAINED_LIST_LINK;

typedef struct CHAINED_LIST
{
	int index;		// >= max(ids) + 1
	int length;
	CHAINED_LIST_LINK *first;
}	CHAINED_LIST;



void ChainedListInit (CHAINED_LIST* p);

int ChainedListRemove (CHAINED_LIST* p, int id);

int ChainedListFind (CHAINED_LIST* p, int id, void **item);

/*
	A new link is allocated and a pointer to its content is given.
*/
int ChainedListNew (CHAINED_LIST *p, void **item, int item_size);

void ChainedListClear (CHAINED_LIST *p);


#endif

