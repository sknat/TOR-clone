/*******************************************************************************

	Library for a simple use of gcrypt - symmetric cyphering
	Modified form the example by Jason Lewis

*******************************************************************************/

#include <stdio.h>
#include <gcrypt.h>



gcry_cipher_hd_t gcryCipherHd;
char * keyRemind = NULL;
char * iniVector = NULL;
size_t keyLength;
size_t blkLength;


int crypto_init()
{

	public_key_length = gcry_cipher_get_algo_keylen (GCRY_CIPHER);
	public_key_blocklength = gcry_cipher_get_algo_blklen (GCRY_CIPHER);
	if (gcry_cipher_open (&gcryCipherHd, GCRY_CIPHER, GCRY_CIPHER_MODE_CBC, 0)) {
		fprintf (stderr, "gcry_cipher_open failed\n");
		return -1;
	}

	iniVector = malloc(blkLength);
	keyRemind = malloc(keyLength);
	return 0;
}

int aesGenKey()
{
	gcry_randomize (iniVector, blkLength, GCRY_STRONG_RANDOM);
	gcry_randomize (keyRemind, keyLength, GCRY_VERY_STRONG_RANDOM);

	if (gcry_cipher_setkey (gcryCipherHd, keyRemind, keyLength) != 0) {
		fprintf (stderr, "gcry_cipher_setkey failed\n");
		return -1;
	}
	return 0;
}

int aesSetKey(char * aesSymKey, char * aesIniVector)
{	
	if (gcry_cipher_setkey(gcryCipherHd, keyRemind, keyLength)) {
		fprintf (stderr, "gcry_cipher_setkey failed\n");
		return -1;
	}
	iniVector = aesIniVector;
	keyRemind = aesSymKey;
	return 0;
}

int aesEncrypt (char * buffer, size_t buffer_len)
{
	//First 4Bytes of the Buffer describes the size of the data
	int n = ((4+buffer_len)/blkLength+1)*blkLength;
	char * buffer_out = malloc(n);
	((size_t *) buffer_out)[0] = buffer_len;
	memcpy (buffer_out+4, buffer, n-4);
	memset (buffer_out+4+buffer_len, 'a', n-4-buffer_len);

	gcry_cipher_setiv (gcryCipherHd, iniVector, blkLength);
	if (gcry_cipher_encrypt(gcryCipherHd, buffer_out, n, NULL, 0)) {
		fprintf (stderr, "gcry_cipher_encrypt failed\n");
		return -1;
	}

	memcpy (buffer, buffer_out, n);
	free (buffer_out);
	return n;
}
 
int aesDecrypt(char * buffer, size_t buffer_len)
{
	gcry_cipher_setiv(gcryCipherHd, iniVector, blkLength);
	if (gcry_cipher_decrypt(gcryCipherHd, buffer, buffer_len, NULL, 0)) {
		fprintf (stderr, "gcry_cipher_decrypt failed\n");
		return -1;
	}

	size_t real_len = ((size_t*) buffer)[0];

	int i;
	for (i=0; i<real_len; i++) {
		buffer[i] = buffer[i+4];
	}

	return real_len;
}

void aesClose()
{
	gcry_cipher_close(gcryCipherHd);
}

int aesImportKey (char * buffer, size_t len)
{
	int i;
	for(i=0; i<len;i++)
	{
		if (i<keyLength) keyRemind[i] = buffer[i];
		else iniVector[i-keyLength] = buffer[i];
	}
	if (gcry_cipher_setkey (gcryCipherHd, keyRemind, keyLength) != 0) {
		fprintf (stderr, "gcry_cipher_setkey failed\n");
		return -1;
	}

	return 0;
}

void aesExportKey(char * txtBuffer)
{
	snprintf(txtBuffer, keyLength+blkLength, "%s%s", keyRemind, iniVector);
}

 /*******************************************************************************

	Library for a simple use of gcrypt - asymmetric cyphering

*******************************************************************************/

int rsaGenKey(gcry_sexp_t * publicKey, gcry_sexp_t * privateKey)
{
	gcry_sexp_t key_specification;
	gcry_sexp_t key;
	
	if(gcry_sexp_new(&key_specification, "(genkey (rsa (nbits 4:2048)))", 0, 1)) 
	{
		printf("Error creating S-expression for RSA keys");
		return -1;
	}

	if(gcry_pk_genkey(&key, key_specification)) 
	{
		printf("Error while generating RSA key.");
		return -1;
	}
	gcry_sexp_release(key_specification);
	
	if (!(*publicKey = gcry_sexp_find_token( key, "public-key", 0 ))) 
	{
		printf( "Error seeking for public part in key." );
		return -1;
	}
	if (!(*privateKey = gcry_sexp_find_token( key, "private-key", 0 ))) 
	{
		printf( "Error seeking for private part in key." );
		return -1;
	}

	gcry_sexp_release(key);
	return 0;
}

int rsaImportKey(char * inBuffer, size_t len, gcry_sexp_t * key)
{
	if(gcry_sexp_new(key, inBuffer, len, 1)) 
	{
		fprintf(stderr,"Failed to import key\n");
		return -1;
	}
	return 0;
}

int rsaExportKey(gcry_sexp_t * key, char * outBuffer)
{
	if(!(gcry_sexp_sprint(*key, OUT_MODE, outBuffer, gcry_sexp_sprint(*key, OUT_MODE, NULL, 0)))) 
	{
		printf("Error while exporting key");
		return -1;
	}
	return 0;
}
 
int rsaEncrypt(char * inBuffer, size_t len, char * outBuffer, gcry_sexp_t publicKey) 
{
	gcry_sexp_t crypt_sexp;
	gcry_sexp_t plain_sexp;
	
	//String to SExpression Conversion
	gcry_mpi_t plain_mpi;
	size_t nscanned;
	if(gcry_mpi_scan(&plain_mpi, GCRYMPI_FMT_USG, inBuffer, len, &nscanned ) ) 	
	{
		printf( "Error while converting input from char to mpi, %i chars scanned",nscanned);
		return -1;
	}
	if(gcry_sexp_build(&plain_sexp, NULL, "(data(flags raw)(value %m))", plain_mpi ) ) 
	{
		printf( "Error while converting input from mpi to Sexpression");	 
		return -1;
	}
	gcry_mpi_release( plain_mpi );
	//Encryption
	if(gcry_pk_encrypt(&crypt_sexp, plain_sexp, publicKey)) 
	{
		printf( "Error during the encryption" );
		return -1;
	}
	// SExpression to String Conversion
	int outlen = gcry_sexp_sprint(crypt_sexp, OUT_MODE, NULL, 0);
	if(!(gcry_sexp_sprint(crypt_sexp, OUT_MODE, outBuffer, outlen))) 
	{
		printf("Error while printing encrypted result");
		return -1;
	}
	gcry_sexp_release(crypt_sexp);
	gcry_sexp_release(plain_sexp);	
	return outlen;
}

int rsaDecrypt(char * inBuffer, size_t len, char * outBuffer, gcry_sexp_t privateKey) 
{
	gcry_sexp_t plain_sexp;
	gcry_sexp_t crypt_sexp;

	if(gcry_sexp_new(&crypt_sexp, inBuffer, len, 1)) 
	{
		printf("Error while reading the encrypted data");	
		return -1;
	}
	if(gcry_pk_decrypt(&plain_sexp, crypt_sexp, privateKey)) 
	{
		printf("Error during the decryption");
		return -1;
	}
	if(!(gcry_sexp_sprint(plain_sexp, OUT_MODE, outBuffer, len))) 
	{
		printf("Error while printing decryption result");
		return -1;
	}

	//removing quotes left by the S-Expression translation
	int i;
	int n = len-2;
	for (i = 0;i<n; i++)
	{
		outBuffer[i]=outBuffer[i+1];
	}
	outBuffer[n]='\0';
	
	gcry_sexp_release(crypt_sexp);
	gcry_sexp_release(plain_sexp);
	return len-2;
}

