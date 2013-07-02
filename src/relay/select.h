/* ################################################################################
							
							Relay - PORC relay

				Methods for porcessing established connections

   ################################################################################*/

#ifndef RELAY_SELECT_H
#define RELAY_SELECT_H

#include "relay_main.h"

int set_fds (int *nfds, fd_set *fds);
int relay_porc_send (int code, int porc_session_id, char *payload, size_t payload_length);
int process_porc_packet(int tls_session_id);
int send_to_porc(int socks_session_id);
int selecting();

#endif