#include <stdio.h>
#include <gcrypt.h>

#define GCRY_CIPHER GCRY_CIPHER_AES256   // Pick the cipher here
#define GCRY_CIPHER_MODE GCRY_CIPHER_MODE_CBC
size_t keyLength, blkLength;

gcry_cipher_hd_t gcryCipherHd;
char * iniVector;

void aesInit(char * aesSymKey, char * _iniVector)
{
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

void main()
{
	/* Version check should be the very first call because it
	makes sure that important subsystems are intialized. */
	if (!gcry_check_version (GCRYPT_VERSION))
	{
		fputs ("libgcrypt version mismatch\n", stderr);
		exit (2);
	}
	
char * txtb = "123456789123456";
size_t txtLength = strlen(txtb)+1;//String + Termination
printf("input text = %s\n", txtb);
printf("text length = %d\n", txtLength);
	aesInit("one test AES keyone test AES key", "a test ini value");
	aesEncrypt(txtb,txtLength);
int index;
printf("encBuffer = ");
for (index = 0; index<txtLength; index++)
    printf("%02X", (unsigned char)txtb[index]);
printf("\n");
	aesInit("one test AES keyone test AES key", "a test ini value");
	aesDecrypt(txtb,txtLength);
printf("decoded = %s\n", txtb);
	aesClose();
}
