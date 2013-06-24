 
#include <stdio.h>
#include <gcrypt.h>
 
#define OUT_MODE GCRYSEXP_FMT_ADVANCED

void die(char * str)
{
	printf("%s\n", str);
	exit(2);
} 
 
void generateKeys(gcry_sexp_t * publicKey, gcry_sexp_t * privateKey)
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

void importKey(char * inBuffer, gcry_sexp_t * key)
{
	if(gcry_sexp_new(key, inBuffer, strlen(inBuffer), 1)) die("Failed to import key");
}

void exportKey(gcry_sexp_t * key, char * outBuffer)
{
	if(!(gcry_sexp_sprint(*key, OUT_MODE, outBuffer, gcry_sexp_sprint(*key, OUT_MODE, NULL, 0)))) 
		die("Error while printing encrypted result");
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
/*
void main()
{ 
	gcry_sexp_t pkey;
	gcry_sexp_t ppkey;
	gcry_sexp_t skey;
	
	char * txt = "123456789123456";
	char * out = malloc(1000);
	char * ret = malloc(1000);
	char * tmpk = malloc(1000);
	rsaInit();
	generateKeys(&pkey, &skey);
	exportKey(&pkey, tmpk);
	importKey(tmpk, &ppkey);
	
	printf("%s\n",txt);
	rsaEncrypt(txt, out, ppkey);
	printf("----------------\n%s\n---------------\n",tmpk);
	rsaDecrypt(out,ret,skey);
	printf("%s\n",ret);
	
    gcry_sexp_release(skey);
	gcry_sexp_release(pkey);
}*/

