/*
 * aes_ccm.h
 *
 *  Created on: Jan 30, 2012
 *      Author: vladislav
 */

#ifndef AES_CCM_H_
#define AES_CCM_H_

#include <contiki.h>
#include <contiki-net.h>
#include <contiki-lib.h>

int encrypt(char* output, char* key, char* nonce, char* plaintext, int plaintext_length, char* additional_data);
int decrypt(char* output, char* key, char* nonce, char* ciphertext, int ciphertext_length, char* additional_data);
#endif /* AES_CCM_H_ */
