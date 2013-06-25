 /*******************************************************************************

	Library for a simple use of gcrypt - asymmetric cyphering

*******************************************************************************/

#include <stdio.h>
#include <gcrypt.h>
 
#define OUT_MODE GCRYSEXP_FMT_ADVANCED
 
void rsaGenKey(gcry_sexp_t * publicKey, gcry_sexp_t * privateKey)
{
	gcry_sexp_t key_specification;
	gcry_sexp_t key;
	
	if(gcry_sexp_new(&key_specification, "(genkey (rsa (nbits 4:2048)))", 0, 1)) die("Error creating S-expression for RSA keys");

	if(gcry_pk_genkey(&key, key_specification)) die("Error while generating RSA key.");
	gcry_sexp_release(key_specification);
	
	if (!(*publicKey = gcry_sexp_find_token( key, "public-key", 0 ))) die( "Error seeking for public part in key." );
	if (!(*privateKey = gcry_sexp_find_token( key, "private-key", 0 ))) die( "Error seeking for private part in key." );

	gcry_sexp_release(key);
}

void rsaImportKey(char * inBuffer, gcry_sexp_t * key)
{
	if(gcry_sexp_new(key, inBuffer, strlen(inBuffer), 1)) die("Failed to import key");
}

void rsaExportKey(gcry_sexp_t * key, char * outBuffer)
{
	if(!(gcry_sexp_sprint(*key, OUT_MODE, outBuffer, gcry_sexp_sprint(*key, OUT_MODE, NULL, 0)))) 
		die("Error while exporting key");
}
 
void rsaEncrypt(char * inBuffer, char * outBuffer, gcry_sexp_t publicKey) 
{
	gcry_sexp_t crypt_sexp;
	gcry_sexp_t plain_sexp;
	
	//String to SExpression Conversion
	gcry_mpi_t plain_mpi;
	if(gcry_mpi_scan(&plain_mpi, GCRYMPI_FMT_STD, inBuffer, strlen(inBuffer), NULL ) ) 
		die("Error while converting input from char to mpi");
	if(gcry_sexp_build(&plain_sexp, NULL, "(data(flags raw)(value %m))", plain_mpi ) ) 
		die( "Error while converting input from mpi to Sexpression");	 
	gcry_mpi_release( plain_mpi );
	//Encryption
	if(gcry_pk_encrypt(&crypt_sexp, plain_sexp, publicKey)) die( "Error during the encryption" );
	// SExpression to String Conversion
	if(!(gcry_sexp_sprint(crypt_sexp, OUT_MODE, outBuffer, gcry_sexp_sprint(crypt_sexp, OUT_MODE, NULL, 0)))) 
		die("Error while printing encrypted result");
	gcry_sexp_release(crypt_sexp);
	gcry_sexp_release(plain_sexp);	
}

void rsaDecrypt(char * inBuffer, char * outBuffer, gcry_sexp_t privateKey) 
{
	gcry_sexp_t plain_sexp;
	gcry_sexp_t crypt_sexp;

	if(gcry_sexp_new(&crypt_sexp, inBuffer, strlen(inBuffer), 1)) die("Error while reading the encrypted data");	
	if(gcry_pk_decrypt(&plain_sexp, crypt_sexp, privateKey)) die("Error during the decryption");
	if(!(gcry_sexp_sprint(plain_sexp, OUT_MODE, outBuffer, strlen(inBuffer)))) die("Error while printing decryption result");

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
		die ("libgcrypt version mismatch\n");
	gcry_control( GCRYCTL_DISABLE_SECMEM ); //No secure memory
	gcry_control( GCRYCTL_ENABLE_QUICK_RANDOM, 0 );
}

