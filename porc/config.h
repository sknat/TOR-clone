/*
	config.h - Global parameters
*/

#ifndef CONFIG
#define CONFIG

#define CERT_FILE	"./cert"
#define KEY_FILE	"./key"
#define ROOT_CA_FILE	"./root-ca.pem"
#define FILE_LIST_RELAYS	"./listrelays"
#define PATH_LIST_RELAYS	"./directory/listrelays"

#define CLIENT_PORT	5555
#define CLIENT_IP	"127.0.0.1"

#define DIRECTORY_PORT	5556
#define DIRECTORY_IP	"127.0.0.1"

#define TARGET_IP	"129.104.201.13"
#define TARGET_PORT	80

 
#define SOCKS_MAX_PENDING 200
#define SOCKS_BUFFER_SIZE 256

#define PORC_MAX_MESSAGE_LENGTH		1024

#define MAX_CIRCUIT_LENGTH 5


#endif
