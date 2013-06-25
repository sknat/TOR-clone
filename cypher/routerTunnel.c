/*******************************************************************************

	Handshake code for the router to create a tunnel

*******************************************************************************/

#include <stdio.h>
#include <gcrypt.h>

#include "utils.c"


void main()
{		
	//Prepare public&private keys
	rsaInit();
	rsaGenKey(&pkey, &skey);
	gcry_sexp_t publicRouterKey;
	gcry_sexp_t privateRouterKey;
	//Wait for somebody asking the public key
//GET
	//Send public key
//SEND publicRouterKey
	//Wait for encoded message
//GET
	//Decrypt (private key) the symmetric key
	char * rawClientSymKey = malloc(MAX);
	char * cryptClientSymKey = malloc(MAX);
	rsaDecrypt(rawClientSymKey,cryptClientSymKey,privateRouterKey);
	gcry_sexp_release(publicRouterKey);
	gcry_sexp_release(privateRouterKey);
	//Send Handshake (symmetric key) HERE : signing handshake?
 	aesInit();
	aesImportKey(rawClientSymKey);
	//Tunnel is open
//USE aesDecrypt/aesEncrypt
	//Closing the tunnel
//SEND close signal to Router
	//Free everything
	aesClose();
}
