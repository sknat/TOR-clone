/*******************************************************************************

	Binding toward symmetric and asymmetric libraries

*******************************************************************************/

#include <stdio.h>
//Methods used by the cypher libraries
void die(char * str)
{
	printf("%s\n", str);
	exit(2);
} 

#define MAX 1000
#include "sym_cypher.c"
#include "asym_cypher.c"

//common methods