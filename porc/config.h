/*
	config.h - Global parameters
*/

#ifndef CONFIG
#define CONFIG

#define CERT_FILE	"./cert"
#define KEY_FILE	"./key"
#define ROOT_CA_FILE	"./root-ca.pem"
#define LIST_RELAYS	"./listrelays"

#define CLIENT_PORT	5555
#define CLIENT_IP	"127.0.0.1"

#define DIRECTORY_PORT	5556
#define DIRECTORY_IP	"127.0.0.1"

#define TARGET_IP	"129.104.201.13"
#define TARGET_PORT	80


#define MAXPENDING 200
#define BUF_SIZE 256

#define MAX_TUNNEL_RELAYS 5
#define PUBLIC_KEY_LEN 565
#define CRYPT_SYM_KEY_LEN 547
#define SYM_KEY_LEN 48


#endif
