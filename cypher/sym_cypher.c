/*******************************************************************************

	Library for a simple use of gcrypt - symmetric cyphering
	Modified form the example by Jason Lewis

*******************************************************************************/
#include <stdio.h>
#include <gcrypt.h>

#define GCRY_CIPHER GCRY_CIPHER_AES256   // Pick the cipher here
#define GCRY_CIPHER_MODE GCRY_CIPHER_MODE_CBC
size_t keyLength, blkLength;

gcry_cipher_hd_t gcryCipherHd;
char * iniVector;

void aesInit(char * aesSymKey, char * _iniVector)
{
	/* Version check should be the very first call because it
	makes sure that important subsystems are intialized. */
	if (!gcry_check_version (GCRYPT_VERSION))
	{
		fputs ("libgcrypt version mismatch\n", stderr);
		exit (2);
	}
	size_t keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER);
	size_t blkLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
    gcry_error_t     gcryError;
	iniVector = _iniVector;
    gcryError = gcry_cipher_open(
        &gcryCipherHd, // gcry_cipher_hd_t *
        GCRY_CIPHER,   // int
        GCRY_CIPHER_MODE,     // int
        0);            // unsigned int
    if (gcryError)
    {
        printf("gcry_cipher_open failed:  %s/%s\n", gcry_strsource(gcryError), gcry_strerror(gcryError));
        return;
    }
	gcryError = gcry_cipher_setkey(gcryCipherHd, aesSymKey, keyLength);
    if (gcryError)
    {
        printf("gcry_cipher_setkey failed:  %s/%s\n", gcry_strsource(gcryError), gcry_strerror(gcryError));
        return;
    }
}

void aesEncrypt(char * txtBuffer, size_t txtLength)
{
	gcry_error_t     gcryError;
	gcryError = gcry_cipher_encrypt(gcryCipherHd, txtBuffer, txtLength, NULL, 0);
    if (gcryError)
    {
        printf("gcry_cipher_encrypt failed:  %s/%s\n", gcry_strsource(gcryError), gcry_strerror(gcryError));
        return;
    }
}
 
 void aesDecrypt(char * txtBuffer, size_t txtLength)
{
	gcry_error_t     gcryError;	
	gcryError = gcry_cipher_decrypt(gcryCipherHd, txtBuffer, txtLength, NULL, 0);
    if (gcryError)
    {
        printf("gcry_cipher_decrypt failed:  %s/%s\n", gcry_strsource(gcryError), gcry_strerror(gcryError));
        return;
    }
}

void aesClose()
{
    gcry_cipher_close(gcryCipherHd);
}

