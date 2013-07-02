/* ################################################################################
							
							Relay - PORC relay

					Methods for accepting connections

   ################################################################################*/


#ifndef RELAY_ACCEPT_H
#define RELAY_ACCEPT_H

#include "relay_main.h"

int handle_connection(int client_socket_descriptor);
int accepting (int listen_socket_descriptor);
void *start_accepting (void *arg);

#endif