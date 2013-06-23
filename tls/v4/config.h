#ifndef CONFIG
#define CONFIG

#define CERT_FILE	"../../relays/relay01.cert"
#define KEY_FILE	"../../relays/relay01.key"

#define ROOT_CA_FILE	"../../root-ca/public/root-ca.pem"


#define CLIENT_PORT	5555
#define CLIENT_IP	"127.0.0.1"

#define RELAY_PORT	5556
#define RELAY_IP	"127.0.0.1"

#define TARGET_IP	"129.104.201.13"
#define TARGET_PORT	80


#define MAXPENDING 200
#define BUF_SIZE 256


#endif
