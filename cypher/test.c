#include <stdio.h>
#include <gcrypt.h>

#define GCRY_CIPHER GCRY_CIPHER_AES256   // Pick the cipher here
#define GCRY_CIPHER_MODE GCRY_CIPHER_MODE_CBC
size_t keyLength, blkLength;

gcry_cipher_hd_t gcryCipherHd;

void aesInit(char * aesSymKey, char * iniVector)
{
	size_t keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER);
	size_t blkLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
    gcry_error_t     gcryError;
	
    gcryError = gcry_cipher_open(
        &gcryCipherHd, // gcry_cipher_hd_t *
        GCRY_CIPHER,   // int
        GCRY_CIPHER_MODE,     // int
        0);            // unsigned int
    if (gcryError)
    {
        printf("gcry_cipher_open failed:  %s/%s\n",
               gcry_strsource(gcryError),
               gcry_strerror(gcryError));
        return;
    }
 
    gcryError = gcry_cipher_setkey(gcryCipherHd, aesSymKey, keyLength);
    if (gcryError)
    {
        printf("gcry_cipher_setkey failed:  %s/%s\n",
               gcry_strsource(gcryError),
               gcry_strerror(gcryError));
        return;
    }
	
	gcryError = gcry_cipher_setiv(gcryCipherHd, iniVector, blkLength);
    if (gcryError)
    {
        printf("gcry_cipher_setiv failed:  %s/%s\n",
               gcry_strsource(gcryError),
               gcry_strerror(gcryError));
        return;
    }
}

void aesEncrypt(char * txtBuffer, char * outBuffer)
{
    size_t txtLength = strlen(txtBuffer)+1; // string plus termination
	gcry_error_t     gcryError;	 
    gcryError = gcry_cipher_encrypt(
        gcryCipherHd, // gcry_cipher_hd_t
        outBuffer,    // void *
        txtLength,    // size_t
        txtBuffer,    // const void *
        txtLength);   // size_t
    if (gcryError)
    {
        printf("gcry_cipher_encrypt failed:  %s/%s\n",
               gcry_strsource(gcryError),
               gcry_strerror(gcryError));
        return;
    }
}
 
 void aesDecrypt(char * txtBuffer, char * outBuffer)
{
    size_t txtLength = strlen(txtBuffer)+1; // string plus termination
    gcry_error_t     gcryError;
    gcryError = gcry_cipher_decrypt(
        gcryCipherHd, // gcry_cipher_hd_t
        outBuffer,    // void *
        txtLength,    // size_t
        txtBuffer,    // const void *
        txtLength);   // size_t
    if (gcryError)
    {
        printf("gcry_cipher_encrypt failed:  %s/%s\n",
               gcry_strsource(gcryError),
               gcry_strerror(gcryError));
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
	
char * txtb = "123456789 abcdefghijklmnopqrstuvwzyz ABCDEFGHIJKLMNOPQRSTUVWZYZ";
size_t txtLength = strlen(txtb)+1; // string plus termination
char * encb = malloc(txtLength);
char * outb = malloc(txtLength);
	
	aesInit("one test AES keyone test AES key", "a test ini value");
	aesEncrypt(txtb, encb);
	
int index;
printf("encBuffer = ");
for (index = 0; index<txtLength; index++)
    printf("%02X", (unsigned char)encb[index]);
printf("\n");
	
	aesInit("one test AES keyone test AES key", "a test ini value");
	aesDecrypt(encb, outb);
	
printf("outBuffer = %s\n", outb);
	
	free(encb);
    free(outb);
	aesClose();
}
