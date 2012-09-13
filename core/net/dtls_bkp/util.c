#include "util.h"
#include "dtls.h"
#include "random.h"
#include "ntpd.h"
#include "hmac_sha2.h"
#if CONIKI_TARGET_AVR_RAVEN
#include "raven-lcd.h"
#endif
#include <avr/io.h>


char* add_record_header(char* buffer, uint8_t type, uint64 seq_num, uint16_t epoch, uint16_t length){
	char *ptr = buffer;
	*ptr = (char) (type & 0xFF); ptr++;
	*ptr = (char) (VERSION_MAJOR & 0xFF); ptr++;
	*ptr = (char) (VERSION_MINOR & 0xFF); ptr++;
	*ptr = (char) ((epoch >> 8) & 0xFF); ptr++;
	*ptr = (char) ((epoch) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 40) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 32) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 24) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 16) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 8) & 0xFF); ptr++;
	*ptr = (char) (seq_num & 0xFF); ptr++;
	*ptr = (char) ((length >> 8) & 0xFF); ptr++;
	*ptr = (char) ((length) & 0xFF); ptr++;
	return ptr;
}

char* add_message_header(char* buffer, uint8_t type, uint16_t message_seq, unsigned long length){
	char* ptr = buffer;
	*ptr = (char) (type & 0xFF); ptr++;
	*ptr = (char) ((length >> 16) & 0xFF); ptr++;
	*ptr = (char) ((length >> 8) & 0xFF); ptr++;
	*ptr = (char) ((length) & 0xFF); ptr++;
	*ptr = (char) ((message_seq >> 8) & 0xFF); ptr++;
	*ptr = (char) ((message_seq) & 0xFF); ptr++;
	*ptr = 0x00; ptr++; *ptr = 0x00; ptr++; *ptr = 0x00; ptr++; //frag_offset = 0
	*ptr = (char) ((length >> 16) & 0xFF); ptr++;
	*ptr = (char) ((length >> 8) & 0xFF); ptr++;
	*ptr = (char) ((length) & 0xFF); ptr++;
	return ptr;
}

void create_hello_request(char* buffer, uint64 seq_num, uint16_t epoch){
	char *ptr = add_record_header(buffer, handshake, seq_num, epoch, 12);
	ptr = add_message_header(ptr, hello_request, 0, 0);
}
void create_helloverify_request(char* buffer, unsigned char* cookie, unsigned long long int seq_num, uint16_t epoch, uint16_t msn){
	char *ptr = add_record_header(buffer, handshake, seq_num, epoch, 31);
	ptr = add_message_header(ptr, hello_verify_request, msn, 19);
	*ptr = 0xFE; ptr++; *ptr = 0xFF; ptr++; //protocolVersion has to be 1.0? strange
	*ptr = 0x10; ptr++; //length of cookie is 16 bytes
	uint8_t i = 0;
	for (i = 0; i < 16; i++){
		*ptr = cookie[i]; ptr++;
	}

}
void create_server_hello(char* buffer, char* random, uint64 seq_num, uint16_t epoch, uint16_t msn) {
	char* ptr = add_record_header(buffer, handshake, seq_num, epoch, 50);
	ptr = add_message_header(ptr, server_hello, msn, 38);
	*ptr = (char) (VERSION_MAJOR & 0xFF);	ptr++;
	*ptr = (char) (VERSION_MINOR & 0xFF);	ptr++;
	uint8_t i;
	if (random==NULL){
		unsigned long current_time = getCurrTime();
		*ptr = (char) ((current_time >> 24) & 0xFF);	ptr++;
		*ptr = (char) ((current_time >> 16) & 0xFF);	ptr++;
		*ptr = (char) ((current_time >> 8) & 0xFF);	ptr++;
		*ptr = (char) ((current_time) & 0xFF);	ptr++;
		random_init(clock_time());
		for (i = 0; i < 28; i++) {
			*ptr = (char) (random_rand() % 128 & 0xFF);
			ptr++;
		}
	} else {
		for (i = 0; i < 32; i++){
			*ptr = random[i];
			ptr++;
		}
	}
	*ptr = 0x00;	ptr++; //session id is null so the length is 0
	*ptr = (char) ((TLS_PSK_WITH_AES_128_CCM_8 >> 8) & 0xFF);	ptr++;
	*ptr = (char) ((TLS_PSK_WITH_AES_128_CCM_8) & 0xFF);	ptr++;
	*ptr = 0x00;	ptr++; //null compression only (length 1 null 0)
	/* SERVER_HELLO_DONE */
	ptr = add_record_header(ptr, handshake, seq_num+1, epoch, 12);
	add_message_header(ptr, server_hello_done, 2, 0);
}

void create_first_server_hello(char* buffer, uint64 seq_num, uint16_t epoch, uint16_t msn){
	create_server_hello(buffer, NULL, seq_num, epoch, msn);
}

void create_next_server_hello(char* buffer, char* random, uint64 seq_num, uint16_t epoch, uint16_t msn){
	create_server_hello(buffer, random, seq_num, epoch, msn);
}

void create_client_hello(char* buffer, char* random, char* cookie, uint8_t cookie_len, uint64 seq_num, uint16_t epoch, uint16_t message_seq) {
	char* ptr = add_record_header(buffer, handshake, seq_num, epoch, 54+cookie_len);
	ptr = add_message_header(ptr, client_hello, message_seq, 42+cookie_len );

	*ptr = (char) (VERSION_MAJOR & 0xFF);	ptr++;
	*ptr = (char) (VERSION_MINOR & 0xFF);	ptr++;
	uint8_t i;
	if (random==NULL){
		unsigned long current_time = getCurrTime();
		*ptr = (char) ((current_time >> 24) & 0xFF);	ptr++;
		*ptr = (char) ((current_time >> 16) & 0xFF);	ptr++;
		*ptr = (char) ((current_time >> 8) & 0xFF);	ptr++;
		*ptr = (char) ((current_time) & 0xFF);	ptr++;

		random_init(clock_time());
		for (i = 0; i < 28; i++) {
			*ptr = (char) (random_rand() % 128 & 0xFF);
			ptr++;
		}
	} else {
		for (i = 0; i < 32; i++) {
			*ptr = random[i];
			ptr++;
		}
	}
	*ptr = 0x00;	ptr++; //session id is null so the length is 0
	//cookie goes here
	*ptr = (char) (cookie_len & 0xFF); ptr++;
	if (cookie!=NULL){
		for (i = 0; i < cookie_len; i++){
			*ptr = cookie[i]; ptr++;
		}
	}
	//cipher suites go here
	*ptr = 0x00;	ptr++;
	*ptr = 0x02;	ptr++; //one cipher suite supported
	*ptr = (char) ((TLS_PSK_WITH_AES_128_CCM_8 >> 8) & 0xFF);	ptr++;
	*ptr = (char) ((TLS_PSK_WITH_AES_128_CCM_8) & 0xFF);	ptr++;
	*ptr = 0x01;	ptr++;
	*ptr = 0x00;	ptr++; //null compression only (length 1 null 0)
}

void create_first_client_hello(char* buffer, uint64 seq_num, uint16_t epoch, uint16_t msn){
	create_client_hello(buffer, NULL, NULL, 0, seq_num, epoch, msn);
}
void create_second_client_hello(char* buffer, char* random, char* cookie, uint8_t cookie_len, uint64 seq_num, uint16_t epoch, uint16_t msn){
	create_client_hello(buffer, random, cookie, cookie_len, seq_num, epoch, msn);
}
void create_client_key_exchange(char* buffer, char* psk_identity, uint16_t psk_identity_length, uint64 seq_num, uint16_t epoch, uint16_t msn){

	char* ptr = add_record_header(buffer, handshake, seq_num, epoch, psk_identity_length+2+12);
	ptr = add_message_header(ptr, client_key_exchange, msn, psk_identity_length+2);

	//next two bytes are the length of the psk identity
	*ptr = (char) ((psk_identity_length >> 8) & 0xFF); ptr++;
	*ptr = (char) (psk_identity_length & 0xFF); ptr++;

	//now comes the actual psk_identity
	uint16_t i;
	for (i = 0; i < psk_identity_length; i++){
		*ptr = psk_identity[i]; ptr++;
	}
}

void create_change_cipher_spec(char* buffer, uint64 seq_num, uint16_t epoch){
	char* ptr = add_record_header(buffer, change_cipher_spec, seq_num, epoch, 1);
	*ptr = 0x01;
}

void create_finished(char* buffer, uint64 seq_num, uint16_t epoch){
	char* ptr = add_record_header(buffer, handshake, seq_num, epoch, 40 );
	*ptr = (char) ((epoch >> 8) & 0xFF); ptr++;
	*ptr = (char) ((epoch) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 40) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 32) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 24) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 16) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 8) & 0xFF); ptr++;
	*ptr = (char) (seq_num & 0xFF);
}
void create_application_data(char* buffer, uint16_t length, uint64 seq_num, uint16_t epoch){
	char* ptr = add_record_header(buffer, application_data, seq_num, epoch, length );
	*ptr = (char) ((epoch >> 8) & 0xFF); ptr++;
	*ptr = (char) ((epoch) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 40) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 32) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 24) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 16) & 0xFF); ptr++;
	*ptr = (char) ((seq_num >> 8) & 0xFF); ptr++;
	*ptr = (char) (seq_num & 0xFF);
}
void create_alert(char* buffer, uint64 seq_num, uint16_t epoch, uint8_t level, uint8_t type) {
	char* ptr = add_record_header(buffer, alert, seq_num, epoch, 2);
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
