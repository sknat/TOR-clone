/*******************************************************************************

	Handshake code for the client to create a tunnel

*******************************************************************************/

#include <stdio.h>
#include <gcrypt.h>

#include "utils.c"

void main()
{	
	rsaInit();
	//Ask for public key of next node
//ASK
	//Wait for Public key
	char * rawRouterPublicKey = malloc(MAX);
//GET rawRouterPublicKey
	gcry_sexp_t routerPublicKey;
	rsaImportKey(rawRouterPublicKey, &routerPublicKey);
	//Encrypt symmetricKey with publicKey
	aesInit();
	aesGenKey();
	char * rawClientSymKey = malloc(MAX);
	char * cryptClientSymKey = malloc(MAX);
	aesExportKey(rawClientSymKey);
	rsaEncrypt(rawClientSymKey, cryptClientSymKey, routerPublicKey);
	gcry_sexp_release(routerPublicKey);
	//Send Encripted SymmetricKey
//SEND cryptClientSymKey
	//Wait for Handshake
	char * rawRouterHSK = malloc(MAX);
//GET rawRouterHSK
	//Decrypt handshake (symmetricKey)
	aesDecrypt(rawRouterHSK);
	//Tunnel is open
//USE aesDecrypt/aesEncrypt
	//Closing the tunnel
//SEND close signal to Router
	//Free everything
	aesClose();
}