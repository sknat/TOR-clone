#ifndef PORC_RSA
#define PORC_RSA

#define OUT_MODE GCRYSEXP_FMT_ADVANCED

#include <gcrypt.h>

int rsaImportKey(char * inBuffer, size_t len, gcry_sexp_t * key);
int rsaGenKey(gcry_sexp_t * publicKey, gcry_sexp_t * privateKey);
int rsaExportKey(gcry_sexp_t * key, char * outBuffer);
int rsaDecrypt(char * inBuffer, size_t len, char * outBuffer, gcry_sexp_t privateKey);
int rsaEncrypt(char * inBuffer, size_t len, char * outBuffer, gcry_sexp_t publicKey);
int rsaInit();


#endif
