/*
	socks - SOCKSv4 module / PORC client accepting thread
*/

#ifndef PORC_ACCEPT
#define PORC_ACCEPT

#include "clientmain.h"


/*
	proxy_socksv4 - Starts a SOCKSv4 proxy that sets up connections.

	When a new client comes, proxy_socksv4 initializes the connection and signal it to the selecting thread.
*/
int proxy_socksv4 (int port);



#endif

