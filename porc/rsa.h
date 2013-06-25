#ifndef PORC_RSA
#define PORC_RSA

#define OUT_MODE GCRYSEXP_FMT_ADVANCED


void rsaGenKey(gcry_sexp_t * publicKey, gcry_sexp_t * privateKey)
void rsaImportKey(char * inBuffer, gcry_sexp_t * key)
void rsaExportKey(gcry_sexp_t * key, char * outBuffer)
void rsaEncrypt(char * inBuffer, char * outBuffer, gcry_sexp_t publicKey) 
void rsaDecrypt(char * inBuffer, char * outBuffer, gcry_sexp_t privateKey) 
void rsaInit()


#endif
