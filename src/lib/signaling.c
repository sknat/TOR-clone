/************************************************

	Sends an interruption to every running programm

************************************************/

#include "signaling.h"


void signal_handler_interrupt (int signum)
{
	printf ("SIGINT reveived !\n");
}

void signal_handler_newstream (int signum)
{
	printf ("SIGUSR1 reveived !\n");
}

int signal_init () {
	struct sigaction act;
	sigset_t signal_set;

	act.sa_handler = &signal_handler_interrupt;
	sigemptyset(&signal_set);
	act.sa_mask = signal_set;
	act.sa_flags = 0;
	/*
	if (sigaction (SIGINT, &act, NULL) != 0) {
		fprintf (stderr, "Error in SIGINT handler initialisation\n");
		return -1;
	}
	*/
	act.sa_handler = &signal_handler_newstream;
	act.sa_mask = signal_set;
	act.sa_flags = 0;
	
	if (sigaction (SIGUSR1, &act, NULL) != 0) {
		fprintf (stderr, "Error in SIGUSR1 handler initialisation\n");
		return -1;
	}
	
	if (sigaddset (&signal_set, SIGUSR1) != 0) {
		fprintf (stderr, "Error in adding a signal to the blocking set\n");
		return -1;
	}
	
	if (pthread_sigmask (SIG_BLOCK, &signal_set, NULL) != 0) {
		fprintf (stderr, "Error setting the signal blocking set\n");
		return -1;
	}
	return 0;
}

