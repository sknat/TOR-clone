#ifndef PORC_SIGNALING
#define PORC_SIGNALING


void signal_handler_interrupt (int signum);
void signal_handler_newstream (int signum);
int signal_init ();

#endif
