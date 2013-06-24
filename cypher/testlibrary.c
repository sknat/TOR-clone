#include <stdio.h>
#include <gcrypt.h>

#include "sym_cypher.c"
#include "asym_cypher.c"

void main()
{	
	int index;
	char * txtb = "1234DBqsdjkcfhskdj?D?N31njhjb,nN?B?NN?B?..5";
	size_t txtLength = 32;//String + Termination must be a multiple of 16 (blocksize) in length
	printf("Input   text = %s\n", txtb);
	printf("Text  length = %d\n", txtLength);
	printf("Input   text = ");
	for (index = 0; index<txtLength; index++)
    printf("%02X", (unsigned char)txtb[index]);
	printf("\n");
	
	aesInit("one test AES keyone test AES key", "a test ini value"); //key size : 32 bytes
	aesEncrypt(txtb,txtLength);
	
	printf("Encoded text = ");
	for (index = 0; index<txtLength; index++)
    printf("%02X", (unsigned char)txtb[index]);
	printf("\n");
	
	aesInit("one test AES keyone test AES key", "a test ini value");
	aesDecrypt(txtb,txtLength);
	
	printf("Decoded text = %s\n", txtb);
	aesClose();
	/***************************************/
	// Test de la cryptographie asymétrique
	/***************************************/
	gcry_sexp_t pkey;
	gcry_sexp_t ppkey;
	gcry_sexp_t skey;
	
	char * txt = "123456789123456";
	char * out = malloc(1000);
	char * ret = malloc(1000);
	char * tmpk = malloc(1000);
	char * tmpsk = malloc(1000);
	rsaInit();
	generateKeys(&pkey, &skey);
	exportKey(&pkey, tmpk);
	exportKey(&skey, tmpsk);
	importKey(tmpk, &ppkey);
	
	printf("%s\n",txt);
	rsaEncrypt(txt, out, ppkey);
	printf("----------------\n%s\n---------------\n",tmpk);
	printf("----------------\n%s\n---------------\n",tmpsk);
	printf("----------------\n%s\n---------------\n",out);
	rsaDecrypt(out,ret,skey);
	printf("%s\n",ret);
	
    gcry_sexp_release(skey);
	gcry_sexp_release(pkey);	
}

