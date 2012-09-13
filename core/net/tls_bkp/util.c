#include "util.h"
#include "tls.h"
#include "random.h"
#include "ntpd.h"
#include "hmac_sha2.h"
#include "raven-lcd.h"
#include <avr/io.h>
//static uint16_t* supported_cipher_suites = {TLS_PSK_WITH_AES_128_CCM_8}; //server


void create_hello_request(char* buffer){
	char *ptr = buffer;
	/* HELLO REQUEST */
	*ptr = (char) (handshake & 0xFF); ptr++;
	*ptr = (char) (VERSION_MAJOR & 0xFF); ptr++;
	*ptr = (char) (VERSION_MINOR & 0xFF);	ptr++;
	*ptr = 0x00;	ptr++;
	*ptr = 0x04;	ptr++; //length of hello request is 4
	*ptr = (char) (hello_request & 0xFF);	ptr++; //TYPE: hello_request
	*ptr = 0x00;	ptr++;
	*ptr = 0x00;	ptr++;
	*ptr = 0x00;	ptr++;
}
void create_server_hello(char* buffer) {
	char *ptr = buffer;
	/* SERVER HELLO */
	*ptr = (char) (handshake & 0xFF); ptr++;
	*ptr = (char) (VERSION_MAJOR & 0xFF); ptr++;
	*ptr = (char) (VERSION_MINOR & 0xFF);	ptr++;
	*ptr = 0x00;	ptr++;
	*ptr = 0x2A;	ptr++; //length of handshake is 42
	*ptr = (char) (server_hello & 0xFF);	ptr++; //TYPE: server_hello
	*ptr = 0x00;	ptr++;
	*ptr = 0x00;	ptr++;
	*ptr = 0x26;	ptr++; //length of 		client_hello is 38
	*ptr = (char) (VERSION_MAJOR & 0xFF);	ptr++;
	*ptr = (char) (VERSION_MINOR & 0xFF);	ptr++;
	unsigned long current_time = getCurrTime();
	*ptr = (char) ((current_time >> 24) & 0xFF);	ptr++;
	*ptr = (char) ((current_time >> 16) & 0xFF);	ptr++;
	*ptr = (char) ((current_time >> 8) & 0xFF);	ptr++;
	*ptr = (char) ((current_time) & 0xFF);	ptr++;
	uint8_t i;
	random_init(clock_time());
	for (i = 0; i < 28; i++) {
		*ptr = (char) (random_rand() % 128 & 0xFF);
		ptr++;
	}
	*ptr = 0x00;	ptr++; //session id is null so the length is 0
	*ptr = (char) ((TLS_PSK_WITH_AES_128_CCM_8 >> 8) & 0xFF);	ptr++;
	*ptr = (char) ((TLS_PSK_WITH_AES_128_CCM_8) & 0xFF);	ptr++;
	*ptr = 0x00;	ptr++; //null compression only (length 1 null 0)
	/* SERVER_HELLO_DONE */
	*ptr = (char) (handshake & 0xFF);	ptr++;
	*ptr = (char) (VERSION_MAJOR & 0xFF);	ptr++;
	*ptr = (char) (VERSION_MINOR & 0xFF);	ptr++;
	*ptr = 0x00;	ptr++;
	*ptr = 0x04;	ptr++;
	*ptr = (char) (server_hello_done & 0xFF);	ptr++;
	*ptr = 0x00;	ptr++;
	*ptr = 0x00;	ptr++;
	*ptr = 0x00;	ptr++;
}

void create_client_hello(char* buffer) {
	char* ptr = buffer;
	*ptr = (char) (handshake & 0xFF);	ptr++;
	*ptr = (char) (VERSION_MAJOR & 0xFF);	ptr++;
	*ptr = (char) (VERSION_MINOR & 0xFF);	ptr++;
	*ptr = 0x00;	ptr++;
	*ptr = 0x2D;	ptr++; //length of handshake is 45
	*ptr = (char) (client_hello & 0xFF);	ptr++; //TYPE: client_hello
	*ptr = 0x00;	ptr++;
	*ptr = 0x00;	ptr++;
	*ptr = 0x29;	ptr++; //length of client_hello is 41
	*ptr = (char) (VERSION_MAJOR & 0xFF);	ptr++;
	*ptr = (char) (VERSION_MINOR & 0xFF);	ptr++;
	unsigned long current_time = getCurrTime();
	*ptr = (char) ((current_time >> 24) & 0xFF);	ptr++;
	*ptr = (char) ((current_time >> 16) & 0xFF);	ptr++;
	*ptr = (char) ((current_time >> 8) & 0xFF);	ptr++;
	*ptr = (char) ((current_time) & 0xFF);	ptr++;
	uint8_t i;
	random_init(clock_time());
	for (i = 0; i < 28; i++) {
		*ptr = (char) (random_rand() % 128 & 0xFF);
		ptr++;
	}
	*ptr = 0x00;	ptr++; //session id is null so the length is 0
	*ptr = 0x00;	ptr++;
	*ptr = 0x02;	ptr++; //one cipher suite supported
	*ptr = (char) ((TLS_PSK_WITH_AES_128_CCM_8 >> 8) & 0xFF);	ptr++;
	*ptr = (char) ((TLS_PSK_WITH_AES_128_CCM_8) & 0xFF);	ptr++;
	*ptr = 0x01;	ptr++;
	*ptr = 0x00;	ptr++; //null compression only (length 1 null 0)
}

void create_client_key_exchange(char* buffer, char* psk_identity, uint16_t psk_identity_length){
	char* ptr = buffer;
	*ptr = (char) (handshake & 0xFF);	ptr++;
	*ptr = (char) (VERSION_MAJOR & 0xFF);	ptr++;
	*ptr = (char) (VERSION_MINOR & 0xFF);	ptr++;
	//length is psk_identity_length + 1 byte for type +
	//3 bytes for handshake length + 2 bytes for psk_length
	uint16_t length = psk_identity_length+6;
	*ptr = (char) ((length >> 8) & 0xFF);	ptr++;
	*ptr = (char) (length & 0xFF);	ptr++;

	*ptr = (char) (client_key_exchange & 0xFF);	ptr++; //TYPE: client_key_exchanged
	unsigned long cke_length = psk_identity_length+2;
	//length of client_key_exchange is psk_identity_length+2
	*ptr = (char) ((cke_length >> 16) & 0xFF);	ptr++;
	*ptr = (char) ((cke_length >> 8) & 0xFF);	ptr++;
	*ptr = (char) (cke_length & 0xFF);	ptr++;

	//next two bytes are the length of the psk identity
	*ptr = (char) ((psk_identity_length >> 8) & 0xFF); ptr++;
	*ptr = (char) (psk_identity_length & 0xFF); ptr++;

	//now comes the actual psk_identity
	uint16_t i;
	for (i = 0; i < psk_identity_length; i++){
		*ptr = psk_identity[i]; ptr++;
	}
}

void create_change_cipher_spec(char* buffer, uint16_t offset){
	char* ptr = buffer+offset;
	*ptr = (char) (change_cipher_spec & 0xFF);	ptr++;
	*ptr = (char) (VERSION_MAJOR & 0xFF);	ptr++;
	*ptr = (char) (VERSION_MINOR & 0xFF);	ptr++;
	*ptr = 0x00; ptr++;
	*ptr = 0x01; ptr++;
	*ptr = 0x01;
}

void create_finished(char* buffer, uint16_t offset, uint64 seq_num, char* finished){
	char* ptr = buffer+offset;
	*ptr = (char) (handshake & 0xFF);	ptr++;
	*ptr = (char) (VERSION_MAJOR & 0xFF);	ptr++;
	*ptr = (char) (VERSION_MINOR & 0xFF);	ptr++;
	*ptr = 0x00; ptr++;
	*ptr = 0x20; ptr++;
	*ptr = (char) ((seq_num >> 56) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 48) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 40) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 32) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 24) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 16) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 8) & 0xFF); ptr++;
	*ptr = (char) (seq_num & 0xFF); ptr++;

}

void create_alert(char* buffer, uint8_t level, uint8_t type) {
	char* ptr = buffer;
	*ptr = (char) (alert & 0xFF);	ptr++;
	*ptr = (char) (VERSION_MAJOR & 0xFF);	ptr++;
	*ptr = (char) (VERSION_MINOR & 0xFF);	ptr++;
	*ptr = 0x00;	ptr++;
	*ptr = 0x02;	ptr++; //length of handshake is 2
	*ptr = (char) (level & 0xFF);	ptr++;
	*ptr = (char) (type & 0xFF);	ptr++;
}

int PRF(char* output,  char* key, int key_length, char* label, char* seed, int seed_length, int output_length){
	char A[32];
	hmac_sha256_ctx c;
	hmac_sha256_init(&c, key, key_length);
	hmac_sha256_update(&c, label, strlen(label));
	hmac_sha256_update(&c, seed, seed_length);
	hmac_sha256_final(&c, A, 32);
	int current_length = 0;
	while (current_length < output_length){
		hmac_sha256_reinit(&c);
		hmac_sha256_update(&c, A, 32);
		hmac_sha256_update(&c, label, strlen(label));
		hmac_sha256_update(&c, seed, seed_length);
		int min = output_length - current_length < 32 ? output_length - current_length : 32;
		hmac_sha256_final(&c, output+current_length, min);
		//change A
		hmac_sha256_reinit(&c);
		hmac_sha256_update(&c, A, 32);
		hmac_sha256_final(&c, A, 32);
		current_length+=32;
	}

	return 1;
}

