#ifndef SOCKS_PROTO
#define SOCKS_PROTO

/* Command constants */
#define CMD_CONNECT 1
#define CMD_BIND 2


/* Connection methods */
#define METHOD_NOAUTH 0
#define METHOD_NOTAVAILABLE 0xff


/* Responses */
#define RESP_SUCCEDED 0x5a
#define RESP_ERROR 0x5b


/* Requests */

typedef struct SOCKS4RequestHeader {
	uint8_t version, cmd;
} __attribute__((packed)) SOCKS4RequestHeader;

typedef struct SOCKS4IP4RequestBody {
	uint16_t port;
	uint32_t ip_dst;
} __attribute__((packed)) SOCKS4IP4RequestBody;


/* Response */

typedef struct SOCKS4Response {
	uint8_t null_byte, status;
	uint16_t rsv1;
	uint32_t rsv2;
} __attribute__((packed)) SOCKS4Response;

#endif

