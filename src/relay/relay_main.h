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



extern int nbr_relays;
extern MYSOCKET *list_relays;



extern pthread_t accepting_thread;
extern pthread_t selecting_thread;



void signal_handler_interrupt (int);
void signal_handler_newstream (int);



#endif