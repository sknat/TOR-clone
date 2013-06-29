#ifndef PORC_CRYPTO
#define PORC_CRYPTO

#include <gcrypt.h>


#define CRYPTO_CIPHER		GCRY_CIPHER_AES256

#define CRYPTO_CIPHER_KEY_LENGTH	32
#define CRYPTO_CIPHER_BLOCK_LENGTH	16


int cryptoInit();

int aesGenKey();
int aesSetKey(char * aesSymKey, char * aesIniVector);
int aesEncrypt (char * buffer, size_t buffer_len);
int aesDecrypt(char * buffer, size_t buffer_len);
void aesClose();
int aesImportKey (char * buffer, size_t len);
void aesExportKey(char * txtBuffer);

int rsaImportKey(char * inBuffer, size_t len, gcry_sexp_t * key);
int rsaGenKey(gcry_sexp_t * publicKey, gcry_sexp_t * privateKey);
int rsaExportKey(gcry_sexp_t * key, char * outBuffer);
int rsaDecrypt(char * inBuffer, size_t len, char * outBuffer, gcry_sexp_t privateKey);
int rsaEncrypt(char * inBuffer, size_t len, char * outBuffer, gcry_sexp_t publicKey);


#endif
