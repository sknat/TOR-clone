/*******************************************************************************

	Library for a simple use of gcrypt - symmetric cyphering
	Modified form the example by Jason Lewis

*******************************************************************************/

#include <stdio.h>
#include <gcrypt.h>

#define GCRY_CIPHER		GCRY_CIPHER_AES256	// Pick the cipher here
#define GCRY_CIPHER_MODE	GCRY_CIPHER_MODE_CBC


gcry_cipher_hd_t gcryCipherHd;
char * keyRemind = NULL;
char * iniVector = NULL;
size_t keyLength;
size_t blkLength;


int aesInit()
{
	/* Version check should be the very first call because it
	makes sure that important subsystems are intialized. */
	if (!gcry_check_version (GCRYPT_VERSION)) {
		fprintf ("libgcrypt version mismatch\n");
		return -1;
	}
	gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
	
	keyLength = gcry_cipher_get_algo_keylen (GCRY_CIPHER);
	blkLength = gcry_cipher_get_algo_blklen (GCRY_CIPHER);
	if (gcry_cipher_open (&gcryCipherHd, GCRY_CIPHER, GCRY_CIPHER_MODE, 0)) {
		fprintf (stderr, "gcry_cipher_open failed\n");
		return -1;
	}

	return 0;
}

void aesGenKey()
{
	if (iniVector != NULL) {
		free (iniVector);
	}
	if (keyRemind != NULL) {
		free (keyRemind);
	}
	iniVector = malloc(blkLength);
	keyRemind = malloc(keyLength);

	gcry_randomize (iniVector, blkLength, GCRY_STRONG_RANDOM);
	gcry_randomize (keyRemind, keyLength, GCRY_VERY_STRONG_RANDOM);

	if (gcry_cipher_setkey (gcryCipherHd, keyRemind, keyLength) != 0) {
		fprintf (stderr, "gcry_cipher_setkey failed\n");
		return -1;
	}
}

void aesSetKey(char * aesSymKey, char * aesIniVector)
{	
	if (gcry_cipher_setkey(gcryCipherHd, keyRemind, keyLength)) {
		fprintf (stderr, "gcry_cipher_setkey failed\n");
		return -1;
	}
	iniVector = aesIniVector;
	keyRemind = aesSymKey;
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

int aesImportKey (char * buffer)
{
	if (iniVector != NULL) {
		free (iniVector);
	}
	if (keyRemind != NULL) {
		free (keyRemind);
	}
	keyRemind = malloc(keyLength);
	iniVector = malloc(blkLength);

	int i;
	for(i=0; i<strlen(buffer);i++)
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


