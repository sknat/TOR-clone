#ifndef PORC_H
#define PORC_H

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

#include "config.h"
#include "mytcp.h"
#include "mytls.h"


extern int nbr_relays;
extern MYSOCKET *list_relays;

/*
	gnutls_global_init must have been called prior to thiese functions
*/
int client_circuit_init ();
int client_circuit_free ();

#endif

