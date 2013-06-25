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

#include "socksproto.h"
#include "config.h"
#include "mytcp.h"
#include "mytls.h"
#include "socks.h"
#include "clientchainedlist.h"
#include "select.h"
#include "porc.h"
#include "signaling.h"



/*
	CLIENT_CIRCUIT - Circuit information for the PORC client.
*/
typedef struct CLIENT_CIRCUIT {
	MYSOCKET relay1;
	gnutls_session_t session;
	int relay1_socket_descriptor;
	MYSOCKET relay2;
	MYSOCKET relay3;
}	CLIENT_CIRCUIT;
CLIENT_CIRCUIT	client_circuit;



extern pthread_t accepting_thread;
extern pthread_t selecting_thread;



void signal_handler_interrupt (int);
void signal_handler_newstream (int);



#endif
