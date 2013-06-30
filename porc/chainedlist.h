/*
	chainedlist - Chained lists for the PORC project.
*/

#ifndef PORC_CHAINED_LIST
#define PORC_CHAINED_LIST

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdlib.h>
#include <stdio.h>
#include <gcrypt.h>
#include "config.h"


typedef struct
{
	int client_socket_descriptor;	// SOCKS client socket descriptor
} 	ITEM_CLIENT;


typedef struct
{
	int socket_descriptor;
	gnutls_session_t gnutls_session;
} 	ITEM_TLS_SESSION;


typedef struct
{
	int id_prev;			// PORC client's id for the PORC session
	int client_tls_session;
	gcry_cipher_hd_t gcry_cipher_hd;
	int final;			// set if the relay is the final relay (then server_tls_session undefined)
	int server_tls_session;
} 	ITEM_PORC_SESSION;


#define SOCKS_TO_TARGET		105
#define SOCKS_TO_RELAY		155

// id is the local SOCKS session id
typedef struct
{
	int id_prev;			// PORC client's id for the SOCKS session
	int client_porc_session;	// PORC session used to communicate with the client
	int target_socket_descriptor;
} 	ITEM_SOCKS_SESSION;




typedef struct CHAINED_LIST_LINK
{
	int id;
	int complete;		// item can be read
	void *item;
	struct CHAINED_LIST_LINK *nxt;
} 	CHAINED_LIST_LINK;

typedef struct
{
	int index;		// >= max(ids) + 1
	int length;
	CHAINED_LIST_LINK *first;
}	CHAINED_LIST;



void ChainedListInit (CHAINED_LIST* p);

int ChainedListRemove (CHAINED_LIST* p, int id);

int ChainedListFind (CHAINED_LIST* p, int id, void **item);

int ChainedListComplete (CHAINED_LIST* p, int id);

/*
	A new link is allocated and a pointer to its content is given.
*/
int ChainedListNew (CHAINED_LIST *p, void **item, int item_size);

int ChainedListNext (CHAINED_LIST_LINK **p, void **item);

void ChainedListClear (CHAINED_LIST *p);


#endif

