#ifndef TLS_H_
#define TLS_H_
#include <contiki.h>
#include <contiki-net.h>
#include <contiki-lib.h>
#include "util.h"
/***************************************************************/
/* 	    		      Defines			       */
/***************************************************************/
#define VERSION_MAJOR 3
#define VERSION_MINOR 3 //TLS 1.2
#define TLS_PSK_WITH_AES_128_CCM_8 0x00a8 //TBD13 from draft-mcgrew-tls-aes-ccm-02 (http://tools.ietf.org/html/draft-mcgrew-tls-aes-ccm-01#page-4)
#define MAX_CONNECTIONS 1
#define READY 0
#define RECV_HEADER 1
#define RECV_MSG 2
#define RECORD_READY 0
#define RECORD_RECV_HEADER 1
#define RECORD_RECV_MSG 2
#define SERVER_HELLO 0x01
#define CLIENT_HELLO 0x02
#define SERVER_HELLO_DONE 0x03
#define CLIENT_KEY_EXCHANGE 0x04
#define CHANGE_CIPHER_SPEC 0x05
#define FINISHED 0x06
#define APPLICATION_DATA 0x07
#define TLS_CONNECTED 1
#define TLS_NEWDATA 2
#define TLS_CLOSED 4
#define TLS_REHANDSHAKE 8
typedef uint8_t uint24_t[3];

typedef struct SecurityParameters {

	char* client_write_key;
	char* server_write_key;
	char* client_write_IV;
	char* server_write_IV;

} SecurityParameters;

typedef struct Connection {
	SecurityParameters* securityParameters;
	struct uip_conn* conn;
} Connection;

typedef struct ProtocolVersion {
	uint8_t major;
	uint8_t minor;
} ProtocolVersion;

enum ContentType {
	change_cipher_spec = 20,
	alert = 21,
	handshake = 22,
	application_data = 23
};

/*
	handshake types (commented out types are not supported)
*/
enum HandshakeType{
	hello_request = 0,
	client_hello = 1,
	server_hello = 2,
//	certificate = 11,
	server_key_exchange = 12,
//	certificate_request = 13,
	server_hello_done = 14,
//	certificate_verify = 15,
	client_key_exchange = 16,
	finished = 20
};

typedef struct Data {
	uip_ipaddr_t *addr;
	uint16_t port;
} Data;

uint8_t tls_flags;

#define tls_connected() (tls_flags & TLS_CONNECTED)
#define tls_newdata() (tls_flags & TLS_NEWDATA)
#define tls_closed() (tls_flags & TLS_CLOSED)
/*
	API function to use when establishing a connection with the server (used by a client)
	ripaddr - IP address of the server
	port - port to connect to
	returns a connection to be used for later communication
*/
void tls_connect(uip_ipaddr_t *ripaddr, uint16_t port);

/*
	Starting to listen for incoming connections (used by a server)
	port - port to listen on
*/
int tls_listen(uint16_t port, uint8_t max_conn);

/*
	Send data over the connection
	conn - connection over which to send the data
	toWrite - data to send  
*/
int tls_write(Connection* conn, char* toWrite, int length);

/*
 * Close the connection
 */
void tls_close(Connection* conn);

process_event_t tls_event;
process_event_t send_event;
char* tls_appdata;
int tls_applen;
PROCESS_NAME(tls_client_handshake_process);
PROCESS_NAME(tls_server_listen);
#endif
