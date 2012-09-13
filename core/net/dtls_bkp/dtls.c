/*
 * dtls.c
 *
 *  Created on: Apr 18, 2012
 *      Author: vladislav
 */

#include "dtls.h"
#include "ntpd.h"
#include "random.h"
#include "hmac_sha2.h"
#include "aes_ccm.h"
#include "string.h"
#include "lib/mmem.h"
#include "raven-lcd.h"
#include <avr/io.h>
#if CONTIKI_TARGET_MINIMAL_NET
#ifndef DEBUG
#define DEBUG DEBUG_PRINT
#endif
#include "net/uip-debug.h"
#endif
/***************************************************************/
/*                     Static variables                        */
/***************************************************************/
static clock_time_t start = 0;
static uint8_t server = 0;
static uint8_t expected_message = SERVER_HELLO;
static uint8_t max_connections = 1;
static uint8_t num_connected = 0;
static uint8_t alert_received = 0;
static uint8_t alert_sent = 0;
static uint8_t sent_something = 0;
static uint8_t handshake_done = 0;
static uint16_t current_epoch = 0;
static uint16_t rcvd_epoch = 0;
static uint64 rcvd_seq = 0;
static uint64 next_receive_seq = 0;
static uint64 next_send_seq = 0;
static uint64 next_send_seq_copy = 0;
static uint16_t sent_message_seq_number = 0;
static uint16_t rcvd_message_seq_number = 0;
static uint8_t first_fragment = 1;
static uint8_t first_data = 1;
static uint8_t first_data_sent = 1;
static uint16_t overall_sent_data = 65535;
static char server_random[32] = "";
static char client_random[32] = "";
static char finished_clear[24] = "";
static char nonce[12] = "";
static char additional_data[13] = "";
static unsigned char cookie_secret[8] = "";
static char handshake_hash[32] = "";
static struct etimer retransmit_timer;
static SecurityParameters* secParam;
static Connection* connection;
static uint8_t send_error = 0;
static struct uip_udp_conn* udp_conn;
static struct process* calling_process;
static struct process* cur_process;
static sha256_ctx ctx;
static sha256_ctx ctxCopy;
static char psk[10] = "secretPSK\0";
static char* psk_identity = "this";
static uint16_t psk_identity_length = 4;
static char* premaster_secret;
static char master_secret[48] = "";
static char client_write_key[16] = "";
static char client_write_IV[4] ="";
static char server_write_key[16] = "";
static char server_write_IV[4] = "";
static struct mmem mmem;
static struct mmem psk_mmem;
static struct mmem message_mmem; //store incoming record if it is fragmented
static struct mmem data_mmem; //store outgoing application data until the new one is ready to be sent
static struct mmem sec_mmem;
static struct mmem conn_mmem;
static char* buffer;
static char internal_error[] = { (char) 0x15, (char) 0xFE, (char) 0xFD,
		(char)0x00,(char)0x00, (char)0x00, (char)0x00,(char)0x00,(char)0x00,
		(char)0x00, (char)0x00, (char) 0x00, (char) 0x02, (char) 0x02, (char) 0x50 };
#define UDP_IP_BUF   ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])
#define RETRANSMIT_INTERVAL 3


/***************************************************************/
/*                   Process definitions                       */
/***************************************************************/
PROCESS(dtls_client_handshake_process, "1");
PROCESS(dtls_server_listen, "2");

static void send(char* data, int length){
#if CONTIKI_TARGET_MINIMAL_NET
	uint8_t i;
	for (i = 0; i < length; i++){
		PRINTF("%02X ", (unsigned char)data[i]);
		if (i%8==7) PRINTF(" ");
		if (i%16==15) PRINTF("\n");
	}
	PRINTF("\n");
#endif
	sent_something = 1;
	uip_udp_packet_send(udp_conn, data, length);
	etimer_set(&retransmit_timer, CLOCK_CONF_SECOND*RETRANSMIT_INTERVAL);
}
static void error(uint8_t level, uint8_t type){
	if (server) num_connected--;

	internal_error[3] = (char)((current_epoch>>8) & 0xFF);
	internal_error[4] = (char)(current_epoch & 0xFF);
	internal_error[5] = (char) ((next_send_seq >> 40) & 0xFF);
	internal_error[6] = (char) ((next_send_seq >> 32) & 0xFF);
	internal_error[7] = (char) ((next_send_seq >> 24) & 0xFF);
	internal_error[8] = (char) ((next_send_seq >> 16) & 0xFF);
	internal_error[9] = (char) ((next_send_seq >> 8) & 0xFF);
	internal_error[10] = (char) (next_send_seq & 0xFF);
	if (type == 80){
		uip_udp_packet_send(udp_conn, internal_error, 15);
	}
	else {
		if(!first_data_sent)mmem_free(&mmem);
		first_data_sent = 1;
		if(mmem_alloc(&mmem, 15)==0){
			uip_udp_packet_send(udp_conn, internal_error, 15);
		} else {
			buffer = (char*)MMEM_PTR(&mmem);
			create_alert(buffer, next_send_seq, current_epoch, level, type);
			uip_udp_packet_send(udp_conn, buffer, 15);
			mmem_free(&mmem);
		}
	}
	send_error = 1;
	alert_sent = type;
}

static void retransmit(){

	switch(expected_message){
	case FIRST_CLIENT_HELLO:
		if (mmem_alloc(&mmem,25)==0){
			error(2,80);
			return;
		}
		buffer = (char*)MMEM_PTR(&mmem);
		create_hello_request(buffer, next_send_seq, current_epoch);
		next_send_seq++;
		send(buffer, 25);
		mmem_free(&mmem);
		break;
	case HELLO_VERIFY_REQUEST:
		if(mmem_alloc(&mmem, 67)==0){
			error(2, 80);
			break;
		} else {
			buffer = (char*)MMEM_PTR(&mmem);
			create_second_client_hello(buffer, client_random, NULL, 0, next_send_seq, current_epoch, sent_message_seq_number);
			next_send_seq++;
			send(buffer, 67);
			mmem_free(&mmem);
		}
		break;
	case SERVER_HELLO:
		if (mmem_alloc(&mmem, 67+psk_identity_length)==0){
			error(2,80);
			return;
		}
		buffer = (char*)MMEM_PTR(&mmem);
		create_second_client_hello(buffer, client_random, psk_identity, psk_identity_length, next_send_seq, current_epoch, sent_message_seq_number);
		send(buffer, 67+psk_identity_length);
		next_send_seq++;
		mmem_free(&mmem);
		break;
	case CLIENT_KEY_EXCHANGE:
		if(mmem_alloc(&mmem, 88)==0){
			error(2, 80);
			return;
		}
		buffer = (char*)MMEM_PTR(&mmem);
		create_next_server_hello(buffer, server_random, next_send_seq, current_epoch, sent_message_seq_number);
		next_send_seq++; //need to increment since the above line creates 2 records
		buffer[13] = 0x02; //wtf? without this buffer[13] magically changes to 0x01 :/
		send(buffer, 88);
		next_send_seq++;
		mmem_free(&mmem);
		break;

	}
	uint8_t i;
	if (server==0){
		if (expected_message == CHANGE_CIPHER_SPEC){

			current_epoch--;
			if(mmem_alloc(&mmem, psk_identity_length+27+14+53)==0){
				error(2, 80);
				return;
			}
			buffer = (char*)MMEM_PTR(&mmem);
			create_client_key_exchange(buffer, psk_identity, psk_identity_length, next_send_seq_copy, current_epoch, sent_message_seq_number);
			next_send_seq_copy++;
			create_change_cipher_spec(buffer+psk_identity_length+27, next_send_seq_copy, current_epoch);
			next_send_seq_copy++;
			current_epoch++; //incrementing the epoch!
			finished_clear[0] = 0x14; //msg_type = finished
			finished_clear[1] = 0x00; finished_clear[2] = 0x00; finished_clear[3] = 0x0c; //length
			finished_clear[4] = (char)((sent_message_seq_number>>8)&0xFF); finished_clear[5] = (char)((sent_message_seq_number) & 0xFF);
			finished_clear[6] = 0x00; finished_clear[7] = 0x00; finished_clear[8] = 0x00; //frag_offset
			finished_clear[9] = 0x00; finished_clear[10] = 0x00; finished_clear[11] = 0x0c; //frag_length
			sha256_final(&ctx, (unsigned char*)handshake_hash);
			PRF(finished_clear+12, master_secret, 48, "client finished", handshake_hash, 32, 12);

			for (i = 0; i < 4; i++){
				nonce[i] = client_write_IV[i];
			}
			memcpy(nonce+4, &current_epoch, 2);
			memcpy(additional_data, &current_epoch, 2);
			for (i = 0; i < 6; i++){
				nonce[6+i] = (char)((next_send_seq >> (8*i))&0xFF);
				additional_data[2+i] = (char)((next_send_seq >> (8*i))&0xFF);
			}
			additional_data[8] = 0x16;
			additional_data[9] = 0xfe;
			additional_data[10] = 0xfd;
			additional_data[11] = 0x00;
			additional_data[12] = 0x18;

			if(!encrypt(buffer+psk_identity_length+27+14+21, client_write_key, nonce, finished_clear, 24, additional_data)){
				mmem_free(&mmem);
				error(2,80);
				return;
			}

			create_finished(buffer+psk_identity_length+27+14, next_send_seq, current_epoch);
			send(buffer, psk_identity_length+94);
			next_send_seq++;
			mmem_free(&mmem);
			sha256_final(&ctxCopy, (unsigned char*)handshake_hash);
		}
	} else {
		if (expected_message == APPLICATION_DATA){
			current_epoch--;
			if(!first_data_sent){
				mmem_free(&mmem);
				first_data_sent = 1;
			}
			if(mmem_alloc(&mmem, 14+53)==0){
				error(2, 80);
				return;
			}
			buffer = (char*)MMEM_PTR(&mmem);
			create_change_cipher_spec(buffer, next_send_seq_copy, current_epoch);
			next_send_seq_copy++;
			current_epoch++; //incrementing the epoch!
			sha256_final(&ctx, (unsigned char*)handshake_hash);
			//create finished_clear
			finished_clear[0] = 0x14; //msg_type = finished
			finished_clear[1] = 0x00; finished_clear[2] = 0x00; finished_clear[3] = 0x0c; //length
			finished_clear[4] = (char)(((sent_message_seq_number+1)>>8)&0xFF); finished_clear[5] = (char)(((sent_message_seq_number+1)) & 0xFF);
			finished_clear[6] = 0x00; finished_clear[7] = 0x00; finished_clear[8] = 0x00; //frag_offset
			finished_clear[9] = 0x00; finished_clear[10] = 0x00; finished_clear[11] = 0x0c; //frag_length

			PRF(finished_clear+12, master_secret, 48, "server finished", handshake_hash, 32, 12);
			for (i = 0; i < 4; i++){
				nonce[i] = server_write_IV[i];
			}
			memcpy(nonce+4, &current_epoch, 2);
			memcpy(additional_data, &current_epoch, 2);
			for (i = 0; i < 6; i++){
				nonce[6+i] = (char)((next_send_seq >> (8*i))&0xFF);
				additional_data[2+i] = (char)((next_send_seq >> (8*i))&0xFF);
			}
			additional_data[8] = 0x16;
			additional_data[9] = 0xfe;
			additional_data[10] = 0xfd;
			additional_data[11] = 0x00;
			additional_data[12] = 0x18;

			if(!encrypt(buffer+14+21, server_write_key, nonce, finished_clear, 24, additional_data)){
				mmem_free(&mmem);
				error(2,80);
				return;
			}
			create_finished(buffer+14, next_send_seq, current_epoch);
			send(buffer, 67);
			next_send_seq++;
			mmem_free(&mmem);
		}
	}
}

static void rehandshake(){
	overall_sent_data=0;
	if(!first_data_sent)mmem_free(&mmem);
	first_data_sent = 1;
	if (!first_data)mmem_free(&data_mmem);
	first_data = 1;
	sha256_init(&ctx);
	if (server){
		if (mmem_alloc(&mmem,25)==0){
			error(2,80);
			return;
		}
		buffer = (char*)MMEM_PTR(&mmem);
		create_hello_request(buffer, next_send_seq, current_epoch);
		next_send_seq++;
		send(buffer, 25);
		expected_message = FIRST_CLIENT_HELLO;
		sent_message_seq_number = 0;
		rcvd_message_seq_number = 0;
		handshake_done = 0;
		mmem_free(&mmem);
	} else {
		sent_message_seq_number = 0;
		rcvd_message_seq_number = 0;
		handshake_done = 0;
		if (mmem_alloc(&mmem, 67)==0){
			error(2,80);
			return;
		}
		buffer = (char*)MMEM_PTR(&mmem);
		create_first_client_hello(buffer, next_send_seq, current_epoch, sent_message_seq_number);
		next_send_seq++;
		uint8_t i;
		for (i = 0; i < 32; i++){
			client_random[i] = buffer[27+i];
		}
		send(buffer, 67);
		mmem_free(&mmem);
		expected_message = HELLO_VERIFY_REQUEST;
	}
	dtls_flags = DTLS_REHANDSHAKE;
	dtls_event = process_alloc_event();
	process_post(PROCESS_BROADCAST, dtls_event, NULL);
}
/***************************************************************/
/*                          API Calls                          */
/***************************************************************/

void dtls_connect(uip_ipaddr_t *ripaddr, uint16_t port) {

#if CONTIKI_TARGET_MINIMAL_NET
mmem_init();
#endif
	server = 0;
	expected_message = HELLO_VERIFY_REQUEST;
	Data data = { ripaddr, port };
	if(mmem_alloc(&sec_mmem, sizeof(SecurityParameters))==0){
		return;
	}
	secParam = (SecurityParameters*)MMEM_PTR(&sec_mmem);
	if(mmem_alloc(&conn_mmem, sizeof(Connection))==0){
		return;
	}
	connection = (Connection*)MMEM_PTR(&conn_mmem);
	calling_process = PROCESS_CURRENT();
	process_start(&dtls_client_handshake_process, (void*) &data);

}

int dtls_listen(uint16_t port, uint8_t max_conn) {

#if CONTIKI_TARGET_MINIMAL_NET
mmem_init();
#endif
	if (max_conn > MAX_CONNECTIONS) {
		return -1;
	}
	server = 1;
	expected_message = FIRST_CLIENT_HELLO;
	max_connections = max_conn;
	if(mmem_alloc(&sec_mmem, sizeof(SecurityParameters))==0){
		return -1;
	}
	secParam = (SecurityParameters*)MMEM_PTR(&sec_mmem);
	if(mmem_alloc(&conn_mmem, sizeof(Connection))==0){
		return -1;
	}
	connection = (Connection*)MMEM_PTR(&conn_mmem);
	calling_process = PROCESS_CURRENT();
	process_start(&dtls_server_listen, (void*) &port);
	return 0;
}

int dtls_write(Connection* conn, char* toWrite, int length){
	if (expected_message != APPLICATION_DATA){
			return -1;
	}
	if(overall_sent_data<length){
		rehandshake();
		return 0;
	}
	overall_sent_data-=length;
	uint8_t i;
	udp_conn = conn->conn;
	for (i = 0; i < 4; i++){
		if (server) nonce[i] = server_write_IV[i];
		else nonce[i] = client_write_IV[i];
	}
	nonce[4] = (char)((current_epoch >> 8) & 0xFF);
	additional_data[0] = nonce[4];
	nonce[5] = (char)((current_epoch) & 0xFF);
	additional_data[1] = nonce[5];
	for (i = 0; i < 6; i++){
		nonce[11-i] = (char)((next_send_seq >> (8*i))&0xFF);
		additional_data[7-i] = (char)((next_send_seq >> (8*i))&0xFF);
	}
	additional_data[8] = 0x17;
	additional_data[9] = 0xfe;
	additional_data[10] = 0xfd;
	additional_data[11] = (char)((length >> 8) & 0xFF);
	additional_data[12] = (char)(length & 0xFF);
	if (!first_data_sent){
		mmem_free(&mmem);
	}
	first_data_sent = 0;
	if(mmem_alloc(&mmem, length+29)==0){
		error(2, 80);
		return -1;
	}
	char* encrypted = (char*)MMEM_PTR(&mmem);
	start = clock_time();
	if (server){
		if(!encrypt(encrypted+21, server_write_key, nonce, toWrite, length, additional_data)){
			mmem_free(&mmem);
			error(2,80);
			return -1;
		}
	} else {
		if(!encrypt(encrypted+21, client_write_key, nonce, toWrite, length, additional_data)){
			mmem_free(&mmem);
			error(2,80);
			return -1;
		}
	}

	create_application_data(encrypted, length+16, next_send_seq, current_epoch);
	next_send_seq++;
	send(encrypted, length+29);
	etimer_stop(&retransmit_timer);

	return 0;
}

void dtls_close(Connection* conn){
	error(1,0);
}

static uint8_t check_finished_correctness(char* finished){
	if (finished[0]!=0x14 || finished[1]!=0x00 ||
			finished[2]!=0x00 || finished[3]!=0x0c){
		return 0;
	}
	if (finished[4] != (char)((rcvd_message_seq_number >> 8)&0xFF) ||
			finished[5] != (char)((rcvd_message_seq_number) & 0xFF)){
		return 0;
	}
	if (finished[6]!=0x00 || finished[7]!=0x00 || finished[8]!=0x00){
		return 0;
	}
	if (finished[9]!=0x00 || finished[10]!=0x00 || finished[11]!=0x0c){
		return 0;
	}
	char out[12];
	if (server){
		PRF(out, master_secret, 48, "client finished", handshake_hash, 32, 12);
		if (strncmp(finished+12,out,12)!=0){
			return 0;
		}
	} else {
		PRF(out, master_secret, 48, "server finished", handshake_hash, 32, 12);
		if (strncmp(finished+12, out, 12)!=0){
			return 0;
		}
	}
	return 1;
}

static void generate_premaster_secret(char* ps, char* localpsk){
	uint16_t n = strlen(localpsk);

	uint8_t i;
	premaster_secret[0]=(char)((n>>8) & 0xFF);
	premaster_secret[1]=(char)(n & 0xFF);
	for (i = 0; i < n; i++){
		premaster_secret[2+i] = 0x00;
		premaster_secret[n+4+i] = localpsk[i];
	}
	premaster_secret[n+2]=(char)((n>>8) & 0xFF);
	premaster_secret[n+3]=(char)(n & 0xFF);

}

static void generate_master_secret(){
	/*
	 * calculate master secret
	 * RFC5246 section 8.1
	 * master_secret = PRF(pre_master_secret, "master secret",
	 * 						ClientHello.random + ServerHello.random)[0..47];
	 */

	char seed[64];
	memcpy(seed, client_random, 32);
	memcpy(seed+32, server_random, 32);
	PRF(master_secret, premaster_secret, 22, "master secret", seed, 64, 48);
	return ;


}

static void generate_keying_material(){

	char seed[64];
	memcpy(seed, server_random, 32);
	memcpy(seed+32, client_random, 32);
	char out[40];
	PRF(out, master_secret, 48, "key expansion", seed, 64, 40);
	memcpy(client_write_key, out, 16);
	memcpy(server_write_key, out+16, 16);
	memcpy(client_write_IV, out+32, 4);
	memcpy(server_write_IV, out+36, 4);

		return ;

}

static void response_to_server_messages(int result){
	if (result!=1){
		error(2, result);
	} else {

		switch(expected_message){
		case HELLO_VERIFY_REQUEST:
			if (mmem_alloc(&mmem, 67+psk_identity_length)==0){
				error(2,80);
				return;
			}
			buffer = (char*)MMEM_PTR(&mmem);
			create_second_client_hello(buffer, client_random, psk_identity, psk_identity_length, next_send_seq, current_epoch, sent_message_seq_number);
			sha256_update(&ctx, (unsigned char*)buffer+13, psk_identity_length+54);
			send(buffer, 67+psk_identity_length);
			next_send_seq++;
			mmem_free(&mmem);
			expected_message = SERVER_HELLO;
			break;
		case SERVER_HELLO:
			/*
			 * generate premaster secret
			 * RFC4279 section 2
			 */

			if(mmem_alloc(&mmem, 2*strlen(psk)+4)==0){
				error(2, 80);
				return;
			}
			premaster_secret = (char*)MMEM_PTR(&mmem);
			generate_premaster_secret(premaster_secret, psk);
			generate_master_secret();
			generate_keying_material();

#if CONTIKI_TARGET_MINIMAL_NET
			uint8_t j;
			PRINTF("client random: ");
			for (j = 0; j < 32; j++){
				PRINTF("%02X ", (unsigned char)client_random[j]);
			}
			PRINTF("\nserver random: ");
			for (j = 0; j < 32; j++){
				PRINTF("%02X ", (unsigned char)server_random[j]);
			}
			PRINTF("\npremaster secret: ");
			for (j = 0; j < 2*strlen(psk)+4; j++){
				PRINTF("%02X ", (unsigned char)premaster_secret[j]);
			}
			PRINTF("\nmaster secret: ");
			for (j = 0; j < 48; j++){
				PRINTF("%02X ", (unsigned char)master_secret[j]);
			}
			PRINTF("\nclient write key: ");
			for (j = 0; j < 16; j++){
				PRINTF("%02X ", (unsigned char)client_write_key[j]);
			}
			PRINTF("\nserver write key: ");
			for (j = 0; j < 16; j++){
				PRINTF("%02X ", (unsigned char)server_write_key[j]);
			}
			PRINTF("\nclient write IV: ");
			for (j = 0; j < 4; j++){
				PRINTF("%02X ", (unsigned char)client_write_IV[j]);
			}
			PRINTF("\nserver write IV: ");
			for (j = 0; j < 4; j++){
				PRINTF("%02X ", (unsigned char)server_write_IV[j]);
			}
			PRINTF("\n");
#endif
			mmem_free(&mmem);
			expected_message = SERVER_HELLO_DONE;
			break;
		case SERVER_HELLO_DONE:
			/*send ClientKeyExchange + ChangeCipherSuite + Finished
			clientKeyExchange has length psk_identity_length+2+12+13 = psk_identity_length+27
			changeCipherSpec has length 14
			Finished has length 53*/

			psk_identity = "this";
			psk_identity_length = 4;
			if(mmem_alloc(&mmem, psk_identity_length+27+14+53)==0){
				error(2, 80);
				return;
			}
			buffer = (char*)MMEM_PTR(&mmem);
			create_client_key_exchange(buffer, psk_identity, psk_identity_length, next_send_seq, current_epoch, sent_message_seq_number);
			next_send_seq++;
			sha256_update(&ctx, (unsigned char*)buffer+13, psk_identity_length+14);

			create_change_cipher_spec(buffer+psk_identity_length+27, next_send_seq, current_epoch);

			next_send_seq++;
			next_send_seq_copy = next_send_seq;
			current_epoch++; //incrementing the epoch!
			next_send_seq=0;

			//copy a sha256 context so that it can be used later for verifying the hash received from the server
			ctxCopy = ctx;
			//encrypt the hash of all previous messages of the handshake!
			sha256_final(&ctx, (unsigned char*)handshake_hash);
			//create finished_clear
			finished_clear[0] = 0x14; //msg_type = finished
			finished_clear[1] = 0x00; finished_clear[2] = 0x00; finished_clear[3] = 0x0c; //length
			finished_clear[4] = (char)(((sent_message_seq_number+1)>>8)&0xFF); finished_clear[5] = (char)(((sent_message_seq_number+1)) & 0xFF);
			finished_clear[6] = 0x00; finished_clear[7] = 0x00; finished_clear[8] = 0x00; //frag_offset
			finished_clear[9] = 0x00; finished_clear[10] = 0x00; finished_clear[11] = 0x0c; //frag_length

			PRF(finished_clear+12, master_secret, 48, "client finished", handshake_hash, 32, 12);
			uint8_t i;
			for (i = 0; i < 4; i++){
				nonce[i] = client_write_IV[i];
			}
			nonce[4] = (char)((current_epoch >> 8) & 0xFF);
			additional_data[0] = nonce[4];
			nonce[5] = (char)((current_epoch) & 0xFF);
			additional_data[1] = nonce[5];
			for (i = 0; i < 6; i++){
				nonce[11-i] = (char)((next_send_seq >> (8*i))&0xFF);
				additional_data[7-i] = (char)((next_send_seq >> (8*i))&0xFF);
			}
			additional_data[8] = 0x16;
			additional_data[9] = 0xfe;
			additional_data[10] = 0xfd;
			additional_data[11] = 0x00;
			additional_data[12] = 0x18;

			if(!encrypt(buffer+psk_identity_length+27+14+21, client_write_key, nonce, finished_clear, 24, additional_data)){
				mmem_free(&mmem);
				error(2,80);
				return;
			}
			//update hash with the made finished message (non encryped or encrypted?)
			//sha256_update(&ctxCopy, (unsigned char*)buffer+psk_identity_length+27+14+13, 40);
			sha256_update(&ctxCopy, (unsigned char*)finished_clear, 24);
			sha256_final(&ctxCopy, (unsigned char*)handshake_hash); //now handshake_hash has everything including the just sent finished message

			create_finished(buffer+psk_identity_length+27+14, next_send_seq, current_epoch);
			send(buffer, psk_identity_length+94);
			next_send_seq++;
			mmem_free(&mmem);
			expected_message = CHANGE_CIPHER_SPEC;

			break;
		case CHANGE_CIPHER_SPEC:
			expected_message = FINISHED;
			break;
		case FINISHED:

			secParam->client_write_IV = client_write_IV;
			secParam->server_write_IV = server_write_IV;
			secParam->client_write_key = client_write_key;
			secParam->server_write_key = server_write_key;

			connection->securityParameters = secParam;
			connection->conn = udp_conn;
			dtls_event = process_alloc_event();
			dtls_flags = DTLS_CONNECTED;
			process_post(PROCESS_BROADCAST, dtls_event, (void*)connection);
			expected_message = APPLICATION_DATA;
			handshake_done = 1;

			break;
		}
	}
}

static void response_to_client_messages(int result){
	if (result!=1){
		error(2, result);
	} else {
		int fd;
		uint8_t i;
		char* localpsk = psk;
		switch(expected_message){
		case FIRST_CLIENT_HELLO:
			//send the helloverify request
			if (mmem_alloc(&mmem, 44)==0){
				error(2,80);
				return;
			}
			buffer = (char*)MMEM_PTR(&mmem);
			create_helloverify_request(buffer, (unsigned char*)psk_identity, next_send_seq, current_epoch, sent_message_seq_number);
			send(buffer, 44);
			next_send_seq++;
			mmem_free(&mmem);
			mmem_free(&psk_mmem);
			expected_message = SECOND_CLIENT_HELLO;
			break;
		case SECOND_CLIENT_HELLO:
			if(mmem_alloc(&mmem, 88)==0){
				error(2, 80);
				return;
			}
			buffer = (char*)MMEM_PTR(&mmem);
			create_first_server_hello(buffer, next_send_seq, current_epoch, sent_message_seq_number);
			next_send_seq++; //need to increment since the above line creates 2 records
			//save server_random
			for (i = 0; i < 32; i++){
				server_random[i] = buffer[27+i];
			}
			//update the hash
			sha256_update(&ctx, (unsigned char*)buffer+13, 50);
			sha256_update(&ctx, (unsigned char*)buffer+76, 12);
			expected_message = CLIENT_KEY_EXCHANGE;
			buffer[13] = 0x02; //wtf? without this buffer[13] magically changes to 0x01 :/
			send(buffer, 88);
			next_send_seq++;
			mmem_free(&mmem);
			mmem_free(&psk_mmem);
			break;
		case CLIENT_KEY_EXCHANGE:
			//lookup PSK based on the psk_identity
			if  (strncmp(psk_identity,"this",4)!=0){
				error(2, 115);
				return;
			}
			mmem_free(&psk_mmem);
			if(mmem_alloc(&mmem, 2*strlen(psk)+4)==0){
				error(2, 80);
				return;
			}
			premaster_secret = (char*)MMEM_PTR(&mmem);

			generate_premaster_secret(premaster_secret, psk);
			generate_master_secret();
			mmem_free(&mmem);

			expected_message = CHANGE_CIPHER_SPEC;

			break;
		case CHANGE_CIPHER_SPEC:
			generate_keying_material();
			expected_message = FINISHED;
			break;
		case FINISHED:
			//send ChangeCipherSpec and Finished
			if(mmem_alloc(&mmem, 14+53)==0){
				error(2, 80);
				return;
			}
			buffer = (char*)MMEM_PTR(&mmem);
			create_change_cipher_spec(buffer, next_send_seq, current_epoch);
			next_send_seq++;
			next_send_seq_copy = next_send_seq;
			current_epoch++; //incrementing the epoch!
			next_send_seq=0;
			sha256_final(&ctx, (unsigned char*)handshake_hash);
			//create finished_clear
			finished_clear[0] = 0x14; //msg_type = finished
			finished_clear[1] = 0x00; finished_clear[2] = 0x00; finished_clear[3] = 0x0c; //length
			finished_clear[4] = (char)(((sent_message_seq_number+1)>>8)&0xFF); finished_clear[5] = (char)(((sent_message_seq_number+1)) & 0xFF);
			finished_clear[6] = 0x00; finished_clear[7] = 0x00; finished_clear[8] = 0x00; //frag_offset
			finished_clear[9] = 0x00; finished_clear[10] = 0x00; finished_clear[11] = 0x0c; //frag_length

			PRF(finished_clear+12, master_secret, 48, "server finished", handshake_hash, 32, 12);
			for (i = 0; i < 4; i++){
				nonce[i] = server_write_IV[i];
			}
			nonce[4] = (char)((current_epoch >> 8) & 0xFF);
			additional_data[0] = nonce[4];
			nonce[5] = (char)((current_epoch) & 0xFF);
			additional_data[1] = nonce[5];
			for (i = 0; i < 6; i++){
				nonce[11-i] = (char)((next_send_seq >> (8*i))&0xFF);
				additional_data[7-i] = (char)((next_send_seq >> (8*i))&0xFF);
			}
			additional_data[8] = 0x16;
			additional_data[9] = 0xfe;
			additional_data[10] = 0xfd;
			additional_data[11] = 0x00;
			additional_data[12] = 0x18;

			if(!encrypt(buffer+14+21, server_write_key, nonce, finished_clear, 24, additional_data)){
				mmem_free(&mmem);
				error(2,80);
				return;
			}
			create_finished(buffer+14, next_send_seq, current_epoch);
			send(buffer, 67);
			next_send_seq++;
			mmem_free(&mmem);
			expected_message = APPLICATION_DATA;

			secParam->client_write_IV = client_write_IV;
			secParam->server_write_IV = server_write_IV;
			secParam->client_write_key = client_write_key;
			secParam->server_write_key = server_write_key;

			connection->securityParameters = secParam;
			connection->conn = udp_conn;
			dtls_event = process_alloc_event();
			dtls_flags = DTLS_CONNECTED;
			process_post(PROCESS_BROADCAST, dtls_event, (void*)connection);

			break;
		}
	}
}
/*
 * return 1 if all good
 * else return the alert type
 */
static int process_server_messages(char* message, int msg_length){
	uint16_t position = 0;
	switch(expected_message){
	case HELLO_VERIFY_REQUEST:
		if ((unsigned char)message[position++] != 0xFE){
			return 47;
		}
		if ((unsigned char)message[position] != 0xFF &&
				(unsigned char)message[position] != 0xFD){
			return 47;
		}
		position++;
		if(msg_length != 3 + message[position]){
			return 47;
		}
		break;
	case SERVER_HELLO:
		if ((unsigned char)message[position++] != 0xFE){
			return 47;
		}
		if ((unsigned char)message[position] != 0xFF &&
				(unsigned char)message[position] != 0xFD){
			return 47;
		}
		position++;

		position += 32; //skip random for now
		position += (message[position] + 1); //skip session id since we don't support it anyway (buffer[position] should always be 0)

		if (message[position++] != (char)((TLS_PSK_WITH_AES_128_CCM_8 >> 8) & 0xFF)){ //server has to return TLS_PSK_WITH_AES_128_CCM_8
			return 40;
		}
		if (message[position++] != (char)((TLS_PSK_WITH_AES_128_CCM_8) & 0xFF)){//otherwise it's a handshake_failure
			return 40;
		}
		if (message[position] != 0x00) //compression method has to be null
			return 40;
		break;
	case SERVER_HELLO_DONE:
		if (msg_length!=0) return 50;
		break;
	case CHANGE_CIPHER_SPEC:
		break;
	case FINISHED:

		break;
	}
	return 1;
}

/*
 * return 1 if all good
 * else return the alert type
 */
static int process_client_messages(char* message, int msg_length){
	uint16_t position = 0;
	int i;
	switch(expected_message){
	case FIRST_CLIENT_HELLO:
	case SECOND_CLIENT_HELLO:
		if ((unsigned char)message[position++] != 0xFE){
			return 47;
		}
		if ((unsigned char)message[position++] != 0xFD) //TLS version has to be 1.2
			return 47;
		position += 32; //skip random for now

		position += (message[position] + 1); //skip session id since we don't support it anyway
		if (position > msg_length){
			return 50;
		}
		if (expected_message == FIRST_CLIENT_HELLO){
			random_init(clock_time());
			for (i = 0; i < 8; i++) {
				cookie_secret[i] = (char) (random_rand() % 128 & 0xFF);
			}
		}
		hmac_sha256_ctx cookie_ctx;
		hmac_sha256_init(&cookie_ctx, cookie_secret, 8);
		hmac_sha256_update(&cookie_ctx, (unsigned char*)message, 34+message[34]+1); //update hash with version, random, session id
		if ((unsigned char)message[position]!=0x00 && (unsigned char)message[position]!=0x10){
			return 47;
		}
		position++;
		if (expected_message == FIRST_CLIENT_HELLO){
			hmac_sha256_update(&cookie_ctx, (unsigned char*)message+position, msg_length - position);
		} else if (expected_message == SECOND_CLIENT_HELLO){
			hmac_sha256_update(&cookie_ctx, (unsigned char*)message+position+16, msg_length - position-16);
		}
		hmac_sha256_update(&cookie_ctx, (unsigned char*)&UDP_IP_BUF->srcipaddr,16);
		if (mmem_alloc(&psk_mmem, 16)==0){
			return 80;
		}
		//to save space psk_identity is now holding the cookie that is sent in the helloverify request
		psk_identity = (char*)MMEM_PTR(&psk_mmem);
		hmac_sha256_final(&cookie_ctx,(unsigned char*)psk_identity, 16);

		if (expected_message == SECOND_CLIENT_HELLO){
			if (strncmp(psk_identity, message+position, 16)!=0){
				expected_message = FIRST_CLIENT_HELLO;
			}
		}
		position += message[position-1];
		uint16_t cs_length = (message[position] << 8) + (message[position + 1]);
		position += 2;
		if (cs_length > msg_length - position || cs_length % 2 == 1){
			return 50;
		}
		uint8_t good = 0;
		while (cs_length/2 > 0) {
			if ((message[position] == (char)(((TLS_PSK_WITH_AES_128_CCM_8 >> 8) & 0xFF)))
					&& (message[position + 1] == (char)((TLS_PSK_WITH_AES_128_CCM_8 & 0xFF)))) {
				good = 1;
				position += cs_length;
				break;
			} else {
				cs_length -= 2;
				position += 2;
			}
		}
		if (!good)
			return 40;
		cs_length = message[position++];
		if (cs_length > msg_length - position){
			return 50;
		}
		good = 0;
		while (cs_length > 0) {
			if (message[position] == 0x00) {
				good = 1;
				position += cs_length;
				break;
			} else {
				cs_length--;
				position++;
			}
		}
		if (!good)
			return 40;
		break;
	case CLIENT_KEY_EXCHANGE:
		break;
	case CHANGE_CIPHER_SPEC:
		break;
	case FINISHED:
		break;
	}
	return 1;
}

static int act_on_full_message(char* message, int msg_length){
	uint8_t i;
	if (expected_message == APPLICATION_DATA){
#if CONTIKI_TARGET_MINIMAL_NET
		PRINTF("APPLICATION DATA DETECTED\n");
#endif
		for (i = 0; i < 4; i++){
			if (server)nonce[i] = client_write_IV[i];
			else nonce[i] = server_write_IV[i];
		}
		nonce[4] = (char)((rcvd_epoch >> 8) & 0xFF);
		additional_data[0] = nonce[4];
		nonce[5] = (char)((rcvd_epoch) & 0xFF);
		additional_data[1] = nonce[5];
		for (i = 0; i < 6; i++){
			nonce[11-i] = (char)((rcvd_seq >> (8*i))&0xFF);
			additional_data[7-i] = (char)((rcvd_seq >> (8*i))&0xFF);
		}
		additional_data[8] = 0x17;
		additional_data[9] = 0xfe;
		additional_data[10] = 0xfd;
		additional_data[11] = (char)(((msg_length-16)>>8)&0xFF);
		additional_data[12] = (char)((msg_length-16)&0xFF);
		if (!first_data)mmem_free(&data_mmem);
		first_data = 0;
		if (mmem_alloc(&data_mmem, msg_length-16)==0){
			error(2,80);
			return 0;
		}
		dtls_appdata = (char*)MMEM_PTR(&data_mmem);
#if CONTIKI_TARGET_MINIMAL_NET
		PRINTF("DECRYPTING...");
#endif
		if (server){
			if(!decrypt(dtls_appdata, client_write_key, nonce, message+8, msg_length-8, additional_data)){
				mmem_free(&data_mmem);
				error(2,20);
				return 0;
			}
		} else {
			if(!decrypt(dtls_appdata, server_write_key, nonce, message+8, msg_length-8, additional_data)){
				mmem_free(&data_mmem);
				error(2,20);
				return 0;
			}
		}
#if CONTIKI_TARGET_MINIMAL_NET
		PRINTF("DECTYPTION SUCCEEDED!");
#endif
		dtls_applen = msg_length - 16;
		dtls_flags = DTLS_NEWDATA;
		dtls_event = process_alloc_event();
		uint8_t res = process_post(calling_process, dtls_event, NULL);
#if CONTIKI_TARGET_MINIMAL_NET
		PRINTF("posting to %s resulted in %d\n", PROCESS_NAME_STRING(calling_process), res);
#endif
		return 1;
	}

	if (server){
		uint8_t result = process_client_messages(message, msg_length);
		if(expected_message == SECOND_CLIENT_HELLO && result == 1){
			//save client_random
			for (i = 0; i < 32; i++){
				client_random[i] = message[2+i];
			}
		}
		if(expected_message == CLIENT_KEY_EXCHANGE && result == 1){
			psk_identity_length = (message[0]<<8)+message[1];
			if (mmem_alloc(&psk_mmem, psk_identity_length)==0){
				error(2,80);
				return 0;
			}
			psk_identity = (char*)MMEM_PTR(&psk_mmem);
			for (i = 0; i < psk_identity_length; i++){
				psk_identity[i] = message[2+i];
			}
		}
		if (expected_message == FINISHED && result == 1){
			for (i = 0; i < 4; i++){
				nonce[i] = client_write_IV[i];
			}
			nonce[4] = (char)((rcvd_epoch >> 8) & 0xFF);
			additional_data[0] = nonce[4];
			nonce[5] = (char)((rcvd_epoch) & 0xFF);
			additional_data[1] = nonce[5];
			for (i = 0; i < 6; i++){
				nonce[11-i] = (char)((rcvd_seq >> (8*i))&0xFF);
				additional_data[7-i] = (char)((rcvd_seq >> (8*i))&0xFF);
			}
			additional_data[8] = 0x16;
			additional_data[9] = 0xfe;
			additional_data[10] = 0xfd;
			additional_data[11] = 0x00;
			additional_data[12] = 0x18;
#if CONTIKI_TARGET_MINIMAL_NET
			PRINTF("\nGOT FINISHED MESSAGE\n");
			PRINTF("nonce: ");
			for (i = 0; i < 12; i++) PRINTF("%02X",(unsigned char)nonce[i]);
			PRINTF("\nadditional data: ");
			for (i = 0; i < 13; i++) PRINTF("%02X", (unsigned char)additional_data[i]);
			PRINTF("\nkey: ");
			for (i = 0; i < 16; i++) PRINTF("%02X", (unsigned char) client_write_key[i]);
			PRINTF("\n");
#endif
			if (mmem_alloc(&mmem, 24)==0){
				error(2,80);
				return 0;
			}
			char* finished_clear = (char*)MMEM_PTR(&mmem);

			if(!decrypt(finished_clear, client_write_key, nonce, message+8, 32, additional_data)){
				mmem_free(&mmem);
				error(2,20);
				return 0;
			}
#if CONTIKI_TARGET_MINIMAL_NET
			PRINTF("\nDECRYPTED FINISHED: ");
			for (i = 0; i < 24; i++){
				PRINTF("%02X ", (unsigned char)finished_clear[i]);
			}
			PRINTF("\n");
#endif
			sha256_ctx ctxCopy = ctx;
			sha256_final(&ctxCopy, (unsigned char*)handshake_hash);

			if (check_finished_correctness(finished_clear)!=1){
				error(2,40);
				mmem_free(&mmem);
				return 0;
			}

			sha256_update(&ctx, (unsigned char*)finished_clear, 24);
			mmem_free(&mmem);
		}
		response_to_client_messages(result);
		if (result!=1) return 0;
	} else {
		uint8_t result = process_server_messages(message, msg_length);

		if(expected_message == SERVER_HELLO && result == 1){
			//save server_random
			for (i = 0; i < 32; i++){
				server_random[i] = message[2+i];
			}
			mmem_free(&psk_mmem);
		}
		if(expected_message == HELLO_VERIFY_REQUEST && result ==1){
			psk_identity_length = message[2];
			if (psk_identity_length > 0){
				if (mmem_alloc(&psk_mmem, psk_identity_length)==0){
					return 80;
				}
				//to save space psk_identity is now holding the cookie that is sent in the helloverify request
				psk_identity = (char*)MMEM_PTR(&psk_mmem);
				for (i = 0; i < psk_identity_length; i++){
					psk_identity[i] = message[3+i];
				}
			}
		}
		if (expected_message == FINISHED && result == 1){

			for (i = 0; i < 4; i++){
				nonce[i] = server_write_IV[i];
			}
			nonce[4] = (char)((rcvd_epoch >> 8) & 0xFF);
			additional_data[0] = nonce[4];
			nonce[5] = (char)((rcvd_epoch) & 0xFF);
			additional_data[1] = nonce[5];
			for (i = 0; i < 6; i++){
				nonce[11-i] = (char)((rcvd_seq >> (8*i))&0xFF);
				additional_data[7-i] = (char)((rcvd_seq >> (8*i))&0xFF);
			}
			additional_data[8] = 0x16;
			additional_data[9] = 0xfe;
			additional_data[10] = 0xfd;
			additional_data[11] = 0x00;
			additional_data[12] = 0x18;

			if (mmem_alloc(&mmem, 24)==0){
				error(2,80);
				return 0;
			}
			char* finished_clear = (char*)MMEM_PTR(&mmem);

			if(!decrypt(finished_clear, server_write_key, nonce, message+8, 32, additional_data)){
				mmem_free(&mmem);
				error(2,20);
				return 0;
			}
			if (check_finished_correctness(finished_clear)!=1){
				error(2,40);
				mmem_free(&mmem);
				return 0;
			}
			mmem_free(&mmem);
		}
		response_to_server_messages(result);
		if (result!=1)return 0;
	}
	return 1;
}

static void process_message(char* message, int msg_length){
#if CONTIKI_TARGET_MINIMAL_NET
	PRINTF("PROCESSING MESSAGE...\n");
#endif
	uint8_t i;
	if (send_error){
		return;
	}
	if (alert_received){
		alert_received = 0;
		etimer_stop(&retransmit_timer);
		if (message[1] == 0){
			error(1,0);
			return;
		} else {
			if (server) num_connected--;
			send_error = 1;
			return;
		}
	}
	if (!server && handshake_done && message[0]==((char)hello_request & 0xFF) && msg_length == 12){
		rehandshake();
		return;
	}
	if (expected_message == APPLICATION_DATA || expected_message == FINISHED || expected_message == CHANGE_CIPHER_SPEC){
		if (act_on_full_message(message, msg_length)==1)etimer_stop(&retransmit_timer);
		return;
	}
		//receive a fragment, check if it's what we expect

	if ((expected_message == FIRST_CLIENT_HELLO && (message[0]!=((char)client_hello & 0xFF))) ||
			(expected_message == CLIENT_KEY_EXCHANGE && (message[0]!=((char)client_key_exchange & 0xFF))) ||
			(expected_message == HELLO_VERIFY_REQUEST && (message[0]!=((char)hello_verify_request & 0xFF)) && message[0]!=((char)server_hello & 0xFF)) ||
			(expected_message == SECOND_CLIENT_HELLO && (message[0]!=((char)client_hello & 0xFF ))) ||
			(expected_message == SERVER_HELLO && (message[0]!=((char)server_hello & 0xFF))) ||
			(expected_message == SERVER_HELLO_DONE && (message[0]!=((char)server_hello_done & 0xFF)))){
		if (alert_sent!=0){
			error(2,alert_sent);
		}
		return;
	}
	etimer_stop(&retransmit_timer);
	if (alert_sent!=0){
		alert_sent = 0;
	}
	if (expected_message != FIRST_CLIENT_HELLO && sent_something == 1) {
		sent_message_seq_number++;
		sent_something = 0;
	}

	//in case cookie exchange isn't used we tell the client to expect server_hello
	if (message[0]== ((char)server_hello & 0xFF)) expected_message = SERVER_HELLO;

	//get the MSN and check whether it's the right one. ignore if it isn't
	uint16_t msg_seq = ((unsigned char)message[4]<<8) + ((unsigned char)message[5]);

	//if it's the first fragment get the length and allocate memory for the whole message
	uint32 frag_length = 0;
	unsigned char* ptr = (unsigned char*)&frag_length;
	*ptr = message[11];
	*(ptr+1) = message[10];
	*(ptr+2) = message[9];

	uint32 frag_offset = 0;
	ptr = (unsigned char*)&frag_offset;
	*ptr = message[8];
	*(ptr+1) = message[7];
	*(ptr+2) = message[6];

	uint32 length =  0;
	ptr = (unsigned char*)&length;
	*ptr = message[3];
	*(ptr+1) = message[2];
	*(ptr+2) = message[1];

	if (first_fragment){
		if (frag_length < length){
			if(mmem_alloc(&message_mmem, length)==0){
				error(2, 80);
				return;
			}
			buffer = (char*)MMEM_PTR(&message_mmem);
			for (i = 0; i < frag_length; i++){
				buffer[frag_offset+i] = message[12+i];
			}
			first_fragment = 0;
			if (msg_length - 12 > frag_length){
				process_message(message+12+frag_length, msg_length-12-frag_length);
			}
		} else {
			//first (and the only) fragment. need to add it to the handshake hash if it isn't first client hello or hello verify request
			if (expected_message != FIRST_CLIENT_HELLO && expected_message != HELLO_VERIFY_REQUEST && expected_message != CHANGE_CIPHER_SPEC){
				sha256_update(&ctx, (unsigned char*)message, length+12);
			}
			if (act_on_full_message(message+12, length)!=1) {
				return;
			}
			rcvd_message_seq_number++;
			//in case one record contained more than one message
			if (msg_length - 12 > length){
				process_message(message+12+length, msg_length-12-length);
			}
		}
	} else {
		for (i = 0; i < frag_length; i++){
			buffer[frag_offset+i] = message[12+i];
		}
		if (frag_length+frag_offset == length){
			char header[12];
			for (i = 0; i < 12; i++){
				header[i] = message[i];
			}
			//change the header to have 0 frag_offset and frag_length = length
			header[6] = header[7] = header[8] = 0;
			header[9] = message[1];
			header[10] = message[2];
			header[11] = message[3];
			sha256_update(&ctx, (unsigned char*)header, 12);
			sha256_update(&ctx, (unsigned char*) buffer, length);
			if (act_on_full_message(buffer, length)!=1) return;
			rcvd_message_seq_number++;
			mmem_free(&message_mmem);
			if (msg_length > frag_length+12){
				first_fragment = 1;
				process_message(message+frag_length+12, msg_length-12-frag_length);
			}
		}
	}

}

static void process_input(char* input, int input_length){
	//according to the DTLS specs, each DTLS record MUST fit into a datagram
	//this means that each received udp packet contains 1+ full DTLS records.
#if CONTIKI_TARGET_MINIMAL_NET
	PRINTF("PROCESSING INPUT...\n");
#endif
	if (server && expected_message == APPLICATION_DATA && !handshake_done && input[0]==0x16){
		retransmit();	//FIXME? - this is a hack to support retransmit of the last flight of messages in case it gets lost
		return;
	}
	if (input[0] == 0x15){
		alert_received = 1;
	} else {
		if (expected_message!=CHANGE_CIPHER_SPEC && expected_message!=APPLICATION_DATA && input[0] != 0x16) {
			//silently ignore invalid messages
			return;
		}
		if (expected_message == CHANGE_CIPHER_SPEC && input[0] != 0x14) {
			//silently ignore invalid messages
			return;
		}
		if (expected_message == APPLICATION_DATA && input[0] != 0x17){
			//silently ignore invalid messages (unless it's a client_hello or a hello_request)
			if (server && input[0]==0x16){
				expected_message = FIRST_CLIENT_HELLO;
				sha256_init(&ctx);
				sent_message_seq_number = 0;
				rcvd_message_seq_number = 0;
				mmem_free(&data_mmem);
				if (!first_data_sent) mmem_free(&mmem);
				first_data_sent = 1;
				first_data = 1;
				handshake_done = 0;
				sent_something = 0;
			} else if (!server && input[0]==0x16){

			} else
			return;
		} else if (expected_message == APPLICATION_DATA && input[0]==0x17){
			handshake_done = 1;
		}
	}
	unsigned char* ptr = (unsigned char*)&rcvd_epoch;
	*ptr = input[4];
	*(ptr+1) = input[3];

	if (rcvd_epoch != current_epoch){
		//ignore
		//return; <<ok this was wrong  //FIXME
	}
	//get the seq_number, check with next_received_seq, if smaller or greater then discard, else process

	ptr = (unsigned char*)&rcvd_seq;
	*ptr = input[10];
	*(ptr+1) = input[9];
	*(ptr+2) = input[8];
	*(ptr+3) = input[7];
	*(ptr+4) = input[6];
	*(ptr+5) = input[5];
	//TODO process record seq number using a sliding window

	//get the length, process the message inside
	uint16_t msg_length = ((unsigned char)input[11]<<8)+((unsigned char)input[12]);

	process_message(input+13, msg_length);
	if (msg_length < input_length - 13){
		process_input(input+13+msg_length, input_length-13-msg_length);
	}

}


static void handshake_event_handler(process_event_t ev, process_data_t data) {
	if (ev == tcpip_event) {
		if (server)process_post(calling_process, ev, data);

		if (uip_newdata()) {
#if CONTIKI_TARGET_MINIMAL_NET
		PRINTF("RECEIVING DATA:\n");
		uint8_t i;
		for (i = 0; i < uip_datalen(); i++){
			PRINTF("%02X ",(unsigned char)((char*)uip_appdata)[i] );
			if (i!=0 && i%15==7)PRINTF(" ");
			if (i!=0 && i%15==0)PRINTF("\n");
		}
#endif

			if (server){
					uip_ipaddr_copy(&udp_conn->ripaddr, &UDP_IP_BUF->srcipaddr);
					udp_conn->rport = UDP_IP_BUF->srcport;
			}
			process_input((char*)uip_appdata, uip_datalen());


		}
	} else if (ev == PROCESS_EVENT_TIMER && etimer_expired(&retransmit_timer)){
		if (server && expected_message == APPLICATION_DATA){}
		else retransmit();

	}
}

/***************************************************************/
/*                         Processes                           */
/***************************************************************/
PROCESS_THREAD(dtls_client_handshake_process, ev, data) {
PROCESS_BEGIN();
#if CONTIKI_TARGET_MINIMAL_NET
	PRINTF("client started\n");
#endif
	cur_process = PROCESS_CURRENT();
	Data* d = (struct Data*) data;
	uint16_t port = d->port;
	  /* new connection with remote host */
	uip_ipaddr_t* addr = d->addr;
#if CONTIKI_TARGET_MINIMAL_NET
	PRINTF("connecting to: ");
	PRINT6ADDR(addr);
	PRINTF(" on port %d\n",port);
#endif
	udp_conn = udp_new(addr, UIP_HTONS(port), NULL);
	current_epoch = 0;
	next_send_seq = 0;
	sent_message_seq_number = 0;
	rcvd_message_seq_number = 0;
	handshake_done = 0;
	sha256_init(&ctx);
	if (mmem_alloc(&mmem,67)==1){
			buffer = (char*)MMEM_PTR(&mmem);
			create_first_client_hello(buffer, next_send_seq, current_epoch, sent_message_seq_number);
			next_send_seq++;
			//save client_random
			uint8_t i;
			for (i = 0; i < 32; i++){
				client_random[i] = buffer[27+i];
			}

			send(buffer, 67);
			mmem_free(&mmem);
			/*  done  */

			while (1) {
				PROCESS_YIELD();
				if (send_error){
					send_error = 0;
					break;
				}
				handshake_event_handler(ev, data);
			}
		}
PROCESS_END();
}

PROCESS_THREAD(dtls_server_listen, ev, data) {
	PROCESS_BEGIN();
#if CONTIKI_TARGET_MINIMAL_NET
	PRINTF("server started\n");
#endif
	cur_process = PROCESS_CURRENT();
	uint16_t port = *(uint16_t*) data;
	udp_conn = udp_new(NULL,UIP_HTONS(0),NULL);
	udp_bind(udp_conn, UIP_HTONS(443));
	sha256_init(&ctx); //initialize the context for the hashing function
	while (1) {
		PROCESS_YIELD();
			handshake_event_handler(ev, data);
			if (send_error==1){
				send_error = 0;
				expected_message = FIRST_CLIENT_HELLO;
				sent_message_seq_number = 0;
				rcvd_message_seq_number = 0;
				current_epoch = 0;
				sent_something = 0;
				next_send_seq = 0;
				first_data = 1;
				first_data_sent = 1;
				handshake_done = 0;
				alert_received = 0;
				alert_sent = 0;
				if (!first_data)mmem_free(&data_mmem);
				first_data = 1;
				sha256_init(&ctx);
				memset(&udp_conn->ripaddr, 0, sizeof(udp_conn->ripaddr));
				udp_conn->rport = 0;

			}
	}
	PROCESS_END();
}

