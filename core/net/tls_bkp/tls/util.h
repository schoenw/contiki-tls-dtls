#ifndef __UTIL_H__
#define __UTIL_H__

#include <contiki.h>

uint8_t process_client_messages(char* buffer, uint16_t msg_length, uint8_t offset, char expected_message);
uint8_t process_server_messages(char* buffer, uint16_t msg_length, uint8_t offset, char expected_message);
int PRF(char* output, char* secret, int secret_length, char* label, char* seed, int seed_length, int size);
void create_server_hello(char* buffer);
void create_client_hello(char* buffer);
void create_client_key_exchange(char* buffer, char* psk_identity, uint16_t psk_identity_length);
void create_change_cipher_spec(char* buffer, uint16_t offset);
void create_finished(char* buffer, uint16_t offset, unsigned long long nonce_expl, char* finished);
void create_application_data(char* buffer, unsigned long long nonce_expl, char* data, uint16_t length);
void create_alert(char* buffer, uint8_t level, uint8_t type);


#endif
