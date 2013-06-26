#ifndef PORC_AES
#define PORC_AES

#include <gcrypt.h>

int aesInit();
int aesGenKey();
int aesSetKey(char * aesSymKey, char * aesIniVector);
int aesEncrypt (char * buffer, size_t buffer_len);
int aesDecrypt(char * buffer, size_t buffer_len);
void aesClose();
int aesImportKey (char * buffer, size_t len);
void aesExportKey(char * txtBuffer);



#endif
