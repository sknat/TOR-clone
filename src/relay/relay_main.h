/* ################################################################################

								Relay - PORC relay

		The PORC relay transfers a stream to another relay or to the target.

   ################################################################################*/

#ifndef PORC_RELAY_MAIN
#define PORC_RELAY_MAIN


#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <gcrypt.h>

#include "../config.h"
#include "../lib/tcp.h"
#include "../lib/tls.h"
#include "../lib/chained_list.h"
#include "../lib/signaling.h"
#include "../lib/porc_protocol.h"

#include "select.h"
#include "accept.h"

gnutls_priority_t priority_cache;

pthread_t accepting_thread;
pthread_t selecting_thread;

gcry_sexp_t public_key; 
gcry_sexp_t private_key;

CHAINED_LIST tls_session_list;
CHAINED_LIST porc_session_list;
CHAINED_LIST socks_session_list;

int main (int argc, char **argv);

#endif
