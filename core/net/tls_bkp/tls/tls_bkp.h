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
#define SERVER_HELLO 0x01
#define CLIENT_HELLO 0x02
#define SERVER_HELLO_DONE 0x03
#define CLIENT_KEY_EXCHANGE 0x04
#define CHANGE_CIPHER_SPEC 0x05
#define FINISHED 0x06
#define DATA 0x07

typedef uint8_t uint24_t[3];

//
//
//enum ConnectionEnd{
//	client,
//	//server
//};
//
//
///*
//	PRF algorithms supported
//*/
//enum PRFAlgorithm{
//	tls_prf_sha256 // default TLS 1.2 PRF which uses HMAC with SHA-256
//};
//
///*
//	Cipher types supported
//*/
//enum CipherType{
//	aead // Authentiated Encryption with Associated Data
//};
//
///*
//	An algorithm to be used for encryption
//*/
//enum BulkCipherAlgorithm{
//	aes
//};
//
///*
//	MAC algorithm to use
//*/
//enum MACAlgorithm{
//	MACnull, //no MAC
//	ccm   //TLS_PSK_WITH_AES_128_CCM_8 uses an authentication tag with a length of 8 octets (64 bits)
//};
//
//enum CompressionMethod{
//	CMnull = (uint8_t)0
//};

typedef struct SecurityParameters {
//	enum ConnectionEnd entity;
//	enum PRFAlgorithm prf_algorithm;
//	enum BulkCipherAlgorithm bulk_cipher_algorithm;
//	enum CipherType cipher_type;
//	uint8_t enc_key_length;
//	uint8_t block_length;
//	uint8_t fixed_iv_length;
//	uint8_t record_iv_length;
//	enum MACAlgorithm mac_algorithm;
//	uint8_t mac_length;
//	uint8_t mac_key_length;
//	enum CompressionMethod compression_algorithm;
//	char master_secret[48];
//	char client_random[32];
//	char server_random[32];
	char* client_write_key;
	char* server_write_key;
	char* client_write_IV;
	char* server_write_IV;

} SecurityParameters;

typedef struct Connection {
	SecurityParameters securityParameters;
	struct uip_conn conn;
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
//
//typedef struct GenericAEADCipher {
//	uint16_t length;
//	char* content;
//} GenericAEADCipher;
//
//typedef struct TLSPlaintextHeader {
//	enum ContentType type;
//	ProtocolVersion version;
//	uint16_t length;
//} PlaintextHeader;
//
//typedef struct TLSPlaintext {
//	PlaintextHeader header;
//	void* fragment;
//} Plaintext;
//
//typedef struct TLSCompressed {
//	enum ContentType type;
//	ProtocolVersion version;
//	uint16_t length;
//	void* fragment;
//} Compressed;
//
//typedef struct TLSCiphertext {
//	enum ContentType type;
//	ProtocolVersion version;
//	uint16_t length;
//	GenericAEADCipher fragment;
//} Ciphertext;
/*
	handshake types (commented out types are not supported)
*/
enum HandshakeType{
//	hello_request = 0,
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
//
//typedef struct Handshake {
//	enum HandshakeType msg_type;
//	uint24_t length;
//	void *body;
//} Handshake;
//
//typedef struct Random {
//	unsigned int gmt_unix_time;
//	char random_bytes[28];
//} Random;
//
//typedef struct ClientHello {
//	ProtocolVersion client_version;
//	Random random;
//	uint8_t sessionIDLength;
//	char* sessionID;
//	uint16_t cipherSuiteLength;
//	uint16_t* cipherSuite;
//	uint8_t compressionMethodLength;
//	enum CompressionMethod* compressionMethod;
//	//Extensions?
//} ClientHello;
//
//typedef struct Data {
//	uip_ipaddr_t *addr;
//	uint16_t port;
//	Connection* conn;
//} Data;
//
/*
	Starts the process, hence needs to be run first before anything else
*/
void TLS_Init(void);
/*
	API function to use when establishing a connection with the server (used by a client)
	ripaddr - IP address of the server
	port - port to connect to
	returns a connection to be used for later communication
*/
void TLS_Connect(uip_ipaddr_t *ripaddr, uint16_t port);

/*
	Starting to listen for incoming connections (used by a server)
	port - port to listen on
*/
int TLS_Listen(uint16_t port, uint8_t max_conn);

/*
	Receive data from the connection and write it to the buffer
	conn - connection from where the data is read
	buf - buffer where the read data is stored
*/
int TLS_Read(Connection* conn, char* buf);

/*
	Send data over the connection
	conn - connection over which to send the data
	toWrite - data to send  
*/
int TLS_Write(Connection* conn, char* toWrite);

process_event_t tls_connected_event;
PROCESS_NAME(tls_client_handshake_process);
PROCESS_NAME(tls_server_listen);
#endif

