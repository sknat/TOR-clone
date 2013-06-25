/*******************************************************************************

	Library for a simple use of gcrypt - symmetric cyphering
	Modified form the example by Jason Lewis

*******************************************************************************/
#include <stdio.h>
#include <gcrypt.h>

#define GCRY_CIPHER GCRY_CIPHER_AES256   // Pick the cipher here
#define GCRY_CIPHER_MODE GCRY_CIPHER_MODE_CBC


gcry_cipher_hd_t gcryCipherHd;
char * keyRemind;
char * iniVector;
size_t keyLength;
size_t blkLength;


void aesInit()
{
	/* Version check should be the very first call because it
	makes sure that important subsystems are intialized. */
	if (!gcry_check_version (GCRYPT_VERSION)) die ("libgcrypt version mismatch");
	gcry_control( GCRYCTL_ENABLE_QUICK_RANDOM, 0 );
	
	keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER);
	blkLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
    if (gcry_cipher_open(&gcryCipherHd, GCRY_CIPHER, GCRY_CIPHER_MODE, 0)) die ("gcry_cipher_open failed");
}

void aesGenKey()
{	
	iniVector = malloc(blkLength);
	keyRemind = malloc(keyLength);
	gcry_randomize(iniVector,blkLength,GCRY_STRONG_RANDOM);
	gcry_randomize(keyRemind,keyLength,GCRY_VERY_STRONG_RANDOM);
    if (gcry_cipher_setkey(gcryCipherHd, keyRemind, keyLength)) die ("gcry_cipher_setkey failed");
}

void aesSetKey(char * aesSymKey, char * aesIniVector)
{	
    if (gcry_cipher_setkey(gcryCipherHd, keyRemind, keyLength)) die ("gcry_cipher_setkey failed");
	iniVector = aesIniVector;
	keyRemind = aesSymKey;
}

int aesEncrypt(char * txtBuffer, size_t txtBufferLen)
{
	//First 4Bytes of the Buffer describes the size of the data
	int n = ((4+txtBufferLen)/blkLength+1)*blkLength;
	char * outBuffer = malloc(n);
	((size_t*) outBuffer)[0]=txtBufferLen;
	memcpy(outBuffer+4,txtBuffer,n-4);
	memset(outBuffer+4+txtBufferLen,'a',n-4-txtBufferLen);

	gcry_cipher_setiv(gcryCipherHd, iniVector, blkLength);
    if (gcry_cipher_encrypt(gcryCipherHd, outBuffer, n, NULL, 0)) die("gcry_cipher_encrypt failed");
	memcpy(txtBuffer,outBuffer,n);
	return n;
}
 
 int aesDecrypt(char * txtBuffer, size_t txtBufferLen)
{
	gcry_cipher_setiv(gcryCipherHd, iniVector, blkLength);
    if (gcry_cipher_decrypt(gcryCipherHd, txtBuffer, txtBufferLen, NULL, 0)) die("gcry_cipher_decrypt failed");
	
	size_t realLen = ((size_t*) txtBuffer)[0];
	char * outBuffer = malloc(realLen);
	memcpy (outBuffer,txtBuffer+4,realLen);
	strcpy(txtBuffer,outBuffer);
	return realLen;
}

void aesClose()
{
    gcry_cipher_close(gcryCipherHd);
}

void aesImportKey(char * txtBuffer)
{
	keyRemind = malloc(keyLength);
	iniVector = malloc(blkLength);
	int i;
	for(i = 0;i<strlen(txtBuffer);i++)
	{
		if (i<keyLength) keyRemind[i] = txtBuffer[i];
		else iniVector[i-keyLength] = txtBuffer[i];
	}
    if (gcry_cipher_setkey(gcryCipherHd, keyRemind, keyLength)) die ("gcry_cipher_setkey failed");
}

void aesExportKey(char * txtBuffer)
{
	snprintf(txtBuffer, keyLength+blkLength, "%s%s", keyRemind, iniVector);
}
