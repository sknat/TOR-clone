#ifndef PORC_AES
#define PORC_AES

int aesInit()
void aesGenKey()
void aesSetKey(char * aesSymKey, char * aesIniVector)
int aesEncrypt (char * buffer, size_t buffer_len)
int aesDecrypt(char * buffer, size_t buffer_len)
void aesClose()
int aesImportKey (char * buffer)
void aesExportKey(char * txtBuffer)



#endif
