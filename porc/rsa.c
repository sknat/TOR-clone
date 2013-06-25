 /*******************************************************************************

	Library for a simple use of gcrypt - asymmetric cyphering

*******************************************************************************/

#include <stdio.h>
#include <gcrypt.h>

#include "rsa.h"
 
void rsaGenKey(gcry_sexp_t * publicKey, gcry_sexp_t * privateKey)
{
	gcry_sexp_t key_specification;
	gcry_sexp_t key;
	
	if(gcry_sexp_new(&key_specification, "(genkey (rsa (nbits 4:2048)))", 0, 1)) 
	{
		printf("Error creating S-expression for RSA keys");
		return;
	}

	if(gcry_pk_genkey(&key, key_specification)) 
	{
		printf("Error while generating RSA key.");
		return;
	}
	gcry_sexp_release(key_specification);
	
	if (!(*publicKey = gcry_sexp_find_token( key, "public-key", 0 ))) 
	{
		printf( "Error seeking for public part in key." );
		return;
	}
	if (!(*privateKey = gcry_sexp_find_token( key, "private-key", 0 ))) 
	{
		printf( "Error seeking for private part in key." );
		return;
	}

	gcry_sexp_release(key);
}

void rsaImportKey(char * inBuffer, gcry_sexp_t * key)
{
	if(gcry_sexp_new(key, inBuffer, strlen(inBuffer), 1)) 
	{
		printf("Failed to import key");
		return;
	}
}

void rsaExportKey(gcry_sexp_t * key, char * outBuffer)
{
	if(!(gcry_sexp_sprint(*key, OUT_MODE, outBuffer, gcry_sexp_sprint(*key, OUT_MODE, NULL, 0)))) 
	{
		printfError while exporting key");
		return;
	}
}
 
void rsaEncrypt(char * inBuffer, char * outBuffer, gcry_sexp_t publicKey) 
{
	gcry_sexp_t crypt_sexp;
	gcry_sexp_t plain_sexp;
	
	//String to SExpression Conversion
	gcry_mpi_t plain_mpi;
	size_t nscanned;
	if(gcry_mpi_scan(&plain_mpi, GCRYMPI_FMT_USG, inBuffer, strlen(inBuffer), &nscanned ) ) 	
	{
		printf( "Error while converting input from char to mpi, %i chars scanned",nscanned);
		return;
	}
	if(gcry_sexp_build(&plain_sexp, NULL, "(data(flags raw)(value %m))", plain_mpi ) ) 
	{
		printf( "Error while converting input from mpi to Sexpression");	 
		return;
	}
	gcry_mpi_release( plain_mpi );
	//Encryption
	if(gcry_pk_encrypt(&crypt_sexp, plain_sexp, publicKey)) 
	{
		printf( "Error during the encryption" );
		return;
	}
	// SExpression to String Conversion
	if(!(gcry_sexp_sprint(crypt_sexp, OUT_MODE, outBuffer, gcry_sexp_sprint(crypt_sexp, OUT_MODE, NULL, 0)))) 
	{
		printf("Error while printing encrypted result");
		return;
	}
	gcry_sexp_release(crypt_sexp);
	gcry_sexp_release(plain_sexp);	
}

void rsaDecrypt(char * inBuffer, char * outBuffer, gcry_sexp_t privateKey) 
{
	gcry_sexp_t plain_sexp;
	gcry_sexp_t crypt_sexp;

	if(gcry_sexp_new(&crypt_sexp, inBuffer, strlen(inBuffer), 1)) 
	{
		printf("Error while reading the encrypted data");	
		return;
	}
	if(gcry_pk_decrypt(&plain_sexp, crypt_sexp, privateKey)) 
	{
		printf("Error during the decryption");
		return;
	}
	if(!(gcry_sexp_sprint(plain_sexp, OUT_MODE, outBuffer, strlen(inBuffer)))) 
	{
		printf("Error while printing decryption result");
		return;
	}

	//removing quotes left by the S-Expression translation
	int i;
	int n = strlen(outBuffer)-4;
	for (i = 0;i<n; i++)
	{
		outBuffer[i]=outBuffer[i+1];
	}
	outBuffer[n]='\0';
	
	gcry_sexp_release(crypt_sexp);
	gcry_sexp_release(plain_sexp);
}

void rsaInit()
{
	/* Version check should be the very first call because it
	makes sure that important subsystems are intialized. */
	if (!gcry_check_version (GCRYPT_VERSION)) 
	{
		printf("libgcrypt version mismatch\n");
		return;
	}
	gcry_control( GCRYCTL_DISABLE_SECMEM ); //No secure memory
	gcry_control( GCRYCTL_ENABLE_QUICK_RANDOM, 0 );
}

