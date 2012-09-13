/*
 * dtls.h
 *
 *  Created on: Apr 16, 2012
 *      Author: vladislav
 */

#ifndef DTLS_H_
#define DTLS_H_

#include <contiki.h>
#include <contiki-net.h>
#include <contiki-lib.h>
#include "util.h"
/***************************************************************/
/* 	    		      Defines			       */
/***************************************************************/
#define VERSION_MAJOR 254
#define VERSION_MINOR 253 //DTLS 1.2
#define TLS_PSK_WITH_AES_128_CCM_8 0x00fd //TBD13 from draft-mcgrew-tls-aes-ccm-02 (http://tools.ietf.org/html/draft-mcgrew-tls-aes-ccm-01#page-4)
#define MAX_CONNECTIONS 1
#define RECORD_READY 0
#define HELLO_REQUEST 0x00
#define SERVER_HELLO 0x01
#define FIRST_CLIENT_HELLO 0x02
#define SECOND_CLIENT_HELLO 0x08
#define HELLO_VERIFY_REQUEST 0x09
#define SERVER_HELLO_DONE 0x03
#define CLIENT_KEY_EXCHANGE 0x04
#define CHANGE_CIPHER_SPEC 0x05
#define FINISHED 0x06
#define APPLICATION_DATA 0x07
#define DTLS_CONNECTED 1
#define DTLS_NEWDATA 2
#define DTLS_CLOSED 4
#define DTLS_REHANDSHAKE 8
typedef uint8_t uint24_t[3];

typedef struct SecurityParameters {

	char* client_write_key;
	char* server_write_key;
	char* client_write_IV;
	char* server_write_IV;

} SecurityParameters;

typedef struct Connection {
	SecurityParameters* securityParameters;
	struct uip_udp_conn* conn;
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
	hello_verify_request = 3,
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

uint8_t dtls_flags;

#define dtls_connected() (dtls_flags & DTLS_CONNECTED)
#define dtls_newdata() (dtls_flags & DTLS_NEWDATA)
#define dtls_closed() (dtls_flags & DTLS_CLOSED)
#define dtls_rehandshake() (dtls_flags & DTLS_REHANDSHAKE)

/*
	API function to use when establishing a connection with the server (used by a client)
	ripaddr - IP address of the server
	port - port to connect to
	returns a connection to be used for later communication
*/
void dtls_connect(uip_ipaddr_t *ripaddr, uint16_t port);

/*
	Starting to listen for incoming connections (used by a server)
	port - port to listen on
*/
int dtls_listen(uint16_t port, uint8_t max_conn);

/*
	Send data over the connection
	conn - connection over which to send the data
	toWrite - data to send
*/
int dtls_write(Connection* conn, char* toWrite, int length);

/*
 * Close the connection
 */
void dtls_close(Connection* conn);

process_event_t dtls_event;
char* dtls_appdata;
int dtls_applen;
PROCESS_NAME(dtls_client_handshake_process);
PROCESS_NAME(dtls_server_listen);

#endif /* DTLS_H_ */
