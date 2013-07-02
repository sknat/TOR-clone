/* ################################################################################
					
			Lirary to send an interruption to every running programm
					
   ################################################################################*/

#ifndef PORC_SIGNALING
#define PORC_SIGNALING

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <pthread.h>

void signal_handler_interrupt (int signum);
void signal_handler_newstream (int signum);
int signal_init ();

#endif
