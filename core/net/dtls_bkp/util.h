#ifndef __UTIL_H__
#define __UTIL_H__

#include <contiki.h>
int PRF(char* output, char* secret, int secret_length, char* label, char* seed,int seed_length, int size);
void create_hello_request(char* buffer, unsigned long long int seq_num, uint16_t epoch);
void create_first_server_hello(char* buffer,unsigned long long int seq_num, uint16_t epoch, uint16_t msn);
void create_next_server_hello(char* buffer, char* random, unsigned long long int seq_num, uint16_t epoch, uint16_t msn);
void create_helloverify_request(char* buffer, unsigned char* cookie, unsigned long long int seq_num, uint16_t epoch, uint16_t msn);
void create_first_client_hello(char* buffer, unsigned long long seq_num, uint16_t epoch, uint16_t msn);
void create_second_client_hello(char* buffer, char* random, char* cookie, uint8_t cookie_len, unsigned long long int seq_num, uint16_t epoch, uint16_t msn);
void create_client_key_exchange(char* buffer, char* psk_identity, uint16_t psk_identity_length, unsigned long long int seq_num, uint16_t epoch, uint16_t msn);
void create_change_cipher_spec(char* buffer, unsigned long long int seq_num, uint16_t epoch);
void create_finished(char* buffer, unsigned long long int seq_num, uint16_t epoch);
void create_application_data(char* buffer, uint16_t length, unsigned long long int seq_num, uint16_t epoch);
void create_alert(char* buffer, unsigned long long int seq_num, uint16_t epoch, uint8_t level, uint8_t type);

#endif
