/*******************************************************************************

	Code for Testing asym_cypher.c & sym_cypher.c with verbose output
	To run it,
	$ make test
	$ ./testlibrary.o

*******************************************************************************/

#include <stdio.h>
#include <gcrypt.h>

#include "utils.c"

void main()
{	
	/***************************************/
	// Testing symmetric cryptography
	/***************************************/

	int index;
	//String + Termination must be a multiple of 16 (blocksize) in length
	char * txtb = "1234DBqsdjkcfhskdj?D?N31njhjb123";
	printf("Input    text = %s\n", txtb);
	printf("Input  length = %d\n", strlen(txtb));
	printf("Input    text = ");
	for (index = 0; index<strlen(txtb); index++)
    printf("%02X", (unsigned char)txtb[index]);
	printf("\n");
	
	aesInit(); //key size : 32 bytes
	//aesSetKey("one test AES keyone test AES key", "a test ini value");
	aesGenKey();
	
	char * tmpkkk = malloc(MAX);
	aesExportKey(tmpkkk);
	//printf("Exported Key = %s\n", tmpkkk);
	aesImportKey(tmpkkk);
	
	aesEncrypt(txtb);
	
	printf("Encoded  text = ");
	for (index = 0; index<strlen(txtb); index++)
    printf("%02X", (unsigned char)txtb[index]);
	printf("\n");
	printf("Encoded length = %d\n", strlen(txtb));

	aesDecrypt(txtb);
	printf("Decoded  text = %s\n", txtb);
	
	aesClose();
	/***************************************/
	// Testing asymmetric cryptography
	/***************************************/
	gcry_sexp_t pkey;
	gcry_sexp_t ppkey;
	gcry_sexp_t skey;
	
	char * txt = "123456789123456abcde";
	char * out = malloc(MAX);
	char * ret = malloc(MAX);
	char * tmpk = malloc(MAX);
	char * tmpsk = malloc(MAX);
	rsaInit();
	rsaGenKey(&pkey, &skey);
	rsaExportKey(&pkey, tmpk);
	rsaImportKey(tmpk, &ppkey);
	
	printf("%s\n",txt);
	rsaEncrypt(txt, out, pkey);
	printf("----------------\n%s\n---------------\n",tmpk);
	printf("----------------\n%s\n---------------\n",out);
	rsaDecrypt(out,ret,skey);
	printf("%s\n",ret);
	
    gcry_sexp_release(skey);
	gcry_sexp_release(pkey);	
}

