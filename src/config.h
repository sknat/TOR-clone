/* ################################################################################

							Global PORC Parameters

   ################################################################################*/

#ifndef CONFIG
#define CONFIG

#define CERT_FILE	"./cert"				
#define KEY_FILE	"./key"					
#define ROOT_CA_FILE	"./root-ca.pem"		
#define FILE_LIST_RELAYS	"./listrelays"  
#define PATH_LIST_RELAYS	"../directory/listrelays"

#define CLIENT_PORT	5558 // SOCKS incoming proxy port
#define CLIENT_IP	"127.0.0.1" // SOCKS incoming proxy address

#define DIRECTORY_PORT	5556 // Directory listening port
#define DIRECTORY_IP	"127.0.0.1" // Directory adress

#define TARGET_IP	"129.104.201.13" 	//Traget ip for the socks_sample_client
#define TARGET_PORT	80					//Traget port for the socks_sample_client

#define SOCKS_MAX_PENDING 200
#define SOCKS_BUFFER_SIZE 256

#define PORC_MAX_PAYLOAD_LENGTH		1024
#define PORC_MAX_PACKET_LENGTH		1024

#define MAX_CIRCUIT_LENGTH 10 //Maximal length of porc circuit

#define CRYPTO_CIPHER		GCRY_CIPHER_AES256 //Symetric cyphering algorithm

#define CRYPTO_CIPHER_KEY_LENGTH	32
#define CRYPTO_CIPHER_BLOCK_LENGTH	16

#define CLIENT_PORC_SESSION_ID		0 //Default Porc Session Id

#endif
