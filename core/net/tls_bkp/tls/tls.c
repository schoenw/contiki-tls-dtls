#include "tls.h"
#include "ntpd.h"
#include "random.h"
#include "raven-lcd.h"
#include <avr/io.h>
#include "hmac_sha2.h"
#include "aes_ccm.h"
#include "string.h"
#define MMEM2 1
#if MMEM2
#include "lib/mmem.h"
#endif
/***************************************************************/
/*                   Process definitions                       */
/***************************************************************/
PROCESS(tls_client_handshake_process, "1");
PROCESS(tls_server_listen, "2");

/***************************************************************/
/*                     Static variables                        */
/***************************************************************/
static struct uip_conn *client_conn;
static uint8_t num_connected = 0;
static uint8_t max_connections = 0;
static char* buffer;
static uint16_t msg_length = 0;
static uint8_t recv_length = 0;
static uint8_t state = READY; //internal state for message processing, one of READY, RECV_HEADER, RECV_MSG
static uint8_t expected_message; //specifies which message should come next during the handshake
static uint8_t send_error = 0;
static uint8_t handshake_done = 0;
static uint8_t server = 0;
static uint8_t alert_received = 0;
static char server_random[32];
static char client_random[32];
static char handshake_hash[32];
static sha256_ctx ctx;
static char* premaster_secret;
static char master_secret[48];
static char client_write_key[16];
static char client_write_IV[4];
static char server_write_key[16];
static char server_write_IV[4];
static uint64 seq_num;
static char psk[32] = "abcdefghijklmnopqrstuvwxyz123456";
static char* psk_identity = "thisisme";
static uint16_t psk_identity_length = 8;
static Connection* connection;
static SecurityParameters* secParam;
static struct mmem mmem;
#if MMEM2
static struct mmem datammem;
static struct mmem process_mmem;
static struct mmem conn_mmem;
static struct mmem sec_mmem;
#endif
static char internal_error[] = { (char) 0x15, (char) 0x03, (char) 0x03,
		(char) 0x00, (char) 0x02, (char) 0x02, (char) 0x50 };

static void tcp_send(char* toSend, int length){
	uip_send(toSend, length);
	tcpip_poll_tcp(client_conn);
}


static void error(uint8_t level, uint8_t type){
	if (server) num_connected--;
	state = READY;
	recv_length = 0;
	sha256_init(&ctx);
	if (type == 80) tcp_send(internal_error, 7);
	else {
#if MMEM2
		if(mmem_alloc(&mmem, 7)==0){
#else
		if(!(buffer= (char*)malloc(7))){
#endif
			tcp_send(internal_error, 7);
		} else {
#if MMEM2
			buffer = (char*)MMEM_PTR(&mmem);
#endif
			create_alert(buffer, level, type);
			tcp_send(buffer, 7);
#if MMEM2
			mmem_free(&mmem);
#else
			free(buffer);
#endif
		}
	}
	send_error = 1;
}

/***************************************************************/
/*                          API Calls                          */
/***************************************************************/

void TLS_Connect(uip_ipaddr_t *ripaddr, uint16_t port) {

	server = 0;
	expected_message = SERVER_HELLO;
	Data data = { ripaddr, port };
#if MMEM2
	if(mmem_alloc(&sec_mmem, sizeof(SecurityParameters))==0){
		return;
	}
	secParam = (SecurityParameters*)MMEM_PTR(&sec_mmem);
	if(mmem_alloc(&conn_mmem, sizeof(Connection))==0){
		return;
	}
	connection = (Connection*)MMEM_PTR(&conn_mmem);
#else
	if (!(secParam = (SecurityParameters*)malloc(sizeof(SecurityParameters)))){
		return;
	}
	if (!(connection = (Connection*)malloc(sizeof(Connection)))){
		return;
	}
#endif
	process_start(&tls_client_handshake_process, (void*) &data);
}

int TLS_Listen(uint16_t port, uint8_t max_conn) {
	if (max_conn > MAX_CONNECTIONS) {
		return -1;
	}
	server = 1;
	expected_message = CLIENT_HELLO;
	max_connections = max_conn;
#if MMEM2
	if(mmem_alloc(&sec_mmem, sizeof(SecurityParameters))==0){
		return -1;
	}
	secParam = (SecurityParameters*)MMEM_PTR(&sec_mmem);
	if(mmem_alloc(&conn_mmem, sizeof(Connection))==0){
		return -1;
	}
	connection = (Connection*)MMEM_PTR(&conn_mmem);
#else
	if (!(secParam = (SecurityParameters*)malloc(sizeof(SecurityParameters)))){
			return -1;
	}
	if (!(connection = (Connection*)malloc(sizeof(Connection)))){
		return -1;
	}
#endif
	process_start(&tls_server_listen, (void*) &port);
	return 0;
}

int TLS_Write(Connection* conn, char* toWrite, int length){
	if (expected_message != APPLICATION_DATA){
		return -1;
	}
	client_conn = conn->conn;
	uint8_t i;
	char nonce[12];
	char additional_data[13];
	if (server)	memcpy(nonce, server_write_IV, 4);
	else memcpy(nonce, client_write_IV, 4);
	for(i = 0; i < 8; i++){
		nonce[4+i] = additional_data[i] = (char)(seq_num>>((7-i)*8) & 0xFF);
	}
	char type = 0x17; //application data
	memcpy(additional_data+8, &type, 1);
	char version[2] = {0x03, 0x03}; //version 3.3
	memcpy(additional_data+9, version, 2);
	memcpy(additional_data+11, &length, 2);
	char* encrypted;
#if MMEM2

	if(mmem_alloc(&mmem, length+21)==0){
		error(2, 80);
		return -1;
	}
	encrypted = (char*)MMEM_PTR(&mmem);
#else
	if (!(encrypted = (char*)malloc(length+21))){
		error(2, 80);
		return -1;
	}
#endif
	if (server) {
		if(!encrypt(encrypted, 13, server_write_key, nonce, toWrite, length, additional_data)) {
#if MMEM2
			mmem_free(&mmem);
#else
			free(encrypted);
#endif
			return -1;
		}
	}
	else {
		if(!encrypt(encrypted, 13, client_write_key, nonce, toWrite, length, additional_data)) {
#if MMEM2
			mmem_free(&mmem);
#else
			free(encrypted);
#endif
			return -1;
		}
	}

	encrypted[0] = (char) (application_data & 0xFF);
	encrypted[1] = (char) (VERSION_MAJOR & 0xFF);
	encrypted[2] = (char) (VERSION_MINOR & 0xFF);
	encrypted[3] = (char) (((length+16) >> 8) & 0xFF);
	encrypted[4] = (char) ((length+16) & 0xFF);
	encrypted[5] = (char) ((seq_num >> 56) & 0xFF);
	encrypted[6] = (char) ((seq_num >> 48) & 0xFF);
	encrypted[7] = (char) ((seq_num >> 40) & 0xFF);
	encrypted[8] = (char) ((seq_num >> 32) & 0xFF);
	encrypted[9] = (char) ((seq_num >> 24) & 0xFF);
	encrypted[10] = (char) ((seq_num >> 16) & 0xFF);
	encrypted[11] = (char) ((seq_num >> 8) & 0xFF);
	encrypted[12] = (char) (seq_num & 0xFF);
	seq_num++;
	tcp_send(encrypted, length+21);
#if MMEM2
			mmem_free(&mmem);
#else
			free(encrypted);
#endif
	return 1;
}

void TLS_Close(Connection* conn){
	client_conn = conn->conn;
	error(1, 0);
}

/***************************************************************/
/*                      Helper functions                       */
/***************************************************************/

static void generate_premaster_secret(char* ps){
	uint16_t n = strlen(psk);
	uint8_t i;
	premaster_secret[0]=(char)((n>>8) & 0xFF);
	premaster_secret[1]=(char)(n & 0xFF);
	for (i = 0; i < n; i++){
		premaster_secret[2+i] = 0x00;
		premaster_secret[n+4+i] = psk[i];
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
	PRF(master_secret, premaster_secret,2*strlen(psk)+4, "master secret", seed, 64, 48);
//	memcpy(master_secret, PRF(premaster_secret,2*strlen(psk)+4, "master secret", seed, 64, 48), 48);

}

static void generate_keying_material(){

	char seed[64];
	memcpy(seed, client_random, 32);
	memcpy(seed+32, server_random, 32);
	//TODO swich server and client
	char out[40];
	PRF(out, master_secret, 48, "key expansion", seed, 32, 40);
	memcpy(client_write_key, out, 16);
	memcpy(server_write_key, out+16, 16);
	memcpy(client_write_IV, out+32, 4);
	memcpy(server_write_IV, out+36, 4);
//	memcpy(client_write_key, PRF(master_secret, 48, "key expansion", seed, 32, 40), 16);
//	memcpy(server_write_key, PRF(master_secret, 48, "key expansion", seed, 32, 40)+16, 16);
//	memcpy(client_write_IV, PRF(master_secret, 48, "key expansion", seed, 32, 40)+32, 4);
//	memcpy(server_write_IV, PRF(master_secret, 48, "key expansion", seed, 32, 40)+36, 4);
}

static uint8_t check_finished_correctness(char* finished){
	if (finished[0]!=0x14 || finished[1]!=0x00 ||
			finished[2]!=0x00 || finished[3]!=0x0c){

		return 0;
	}
	char out[12];
	if (server){
		PRF(out, master_secret, 48, "client finished", handshake_hash, 32, 12);
		if (strncmp(finished+4,out,12)!=0){
			return 0;
		}
	} else {
		PRF(out, master_secret, 48, "server finished", handshake_hash, 32, 12);
		if (strncmp(finished+4, out, 12)!=0){
			return 0;
		}
	}
	return 1;
}


static void response_to_client_messages(uint8_t result) {
	if (result == 1) {
		char finished_clear[16];
		char nonce[12];
		char additional_data[13];
		switch(expected_message){
		case CLIENT_HELLO:
#if MMEM2
			if(mmem_alloc(&mmem, 56)==0){
				error(2, 80);
				return;
			}
			buffer = (char*)MMEM_PTR(&mmem);
#else
			if (!(buffer = (char*) malloc(56))) {
				error(2,80);
				return;
			}
#endif
			create_server_hello(buffer);
			//save server_random
			memcpy(server_random,buffer+11,32);
			//update the hash
			sha256_update(&ctx, (unsigned char*)buffer+5, 42);
			sha256_update(&ctx, (unsigned char*)buffer+52, 4);
			expected_message = CLIENT_KEY_EXCHANGE;
			tcp_send(buffer, 56);
#if MMEM2
			mmem_free(&mmem);
#else
			free(buffer);
#endif
			break;
		case CLIENT_KEY_EXCHANGE:
			//lookup PSK based on the psk_identity
			//TODO
			//generate premaster secret
#if MMEM2
			if(mmem_alloc(&mmem, 2*strlen(psk)+4)==0){
				error(2, 80);
				return;
			}
			premaster_secret = (char*)MMEM_PTR(&mmem);
#else
			if(!(premaster_secret = (char*)malloc(2*strlen(psk)+4))){
				error(2,80);
				return;
			}
#endif
			generate_premaster_secret(premaster_secret);
			generate_master_secret();
#if MMEM2
			mmem_free(&mmem);
#else
			free(premaster_secret);
#endif
			expected_message = CHANGE_CIPHER_SPEC;
			break;
		case CHANGE_CIPHER_SPEC:
			generate_keying_material();
			expected_message = FINISHED;
			break;
		case FINISHED:

			//send ChangeCipherSpec and Finished
#if MMEM2
			if(mmem_alloc(&mmem, 6+37)==0){
					error(2, 80);
					return;
			}
			buffer = (char*)MMEM_PTR(&mmem);
#else
			if (!(buffer = (char*) malloc(6 + 37))) {
				error(2,80);
				return;
			}
#endif
			create_change_cipher_spec(buffer, 0);
			//encrypt the hash of all previous messages of the handshake!
			sha256_final(&ctx, (unsigned char*)handshake_hash);

			finished_clear[0] = 0x14; //msg_type = finished
			finished_clear[1] = 0x00; finished_clear[2] = 0x00; finished_clear[3] = 0x0c; //length
			PRF(finished_clear+4, master_secret, 48, "server finished", handshake_hash, 32, 12);
			//memcpy(finished_clear+4, PRF(master_secret, 48, "server finished", handshake_hash, 32, 12), 12);

			seq_num = 0;
			memcpy(nonce, server_write_IV, 4);
			memcpy(nonce+4, &seq_num, 8);
			memcpy(additional_data, &seq_num, 8);
			char type = 0x16; //handshake
			memcpy(additional_data+8, &type ,1);
			char version[2] = {0x03, 0x03}; //version 3.3
			memcpy(additional_data+9, version, 2);
			uint16_t length = 16; //length of the finished record
			memcpy(additional_data+11, &length, 2);

			if(!encrypt(buffer, 6+13, server_write_key, nonce, finished_clear, 16, additional_data)){
#if MMEM2
				mmem_free(&mmem);
#else
				free(buffer);
#endif
				error(2, 80);
				return;
			}
			create_finished(buffer, 6, seq_num,"");
			tcp_send(buffer, 6+37);
#if MMEM2
			mmem_free(&mmem);
#else
			free(buffer);
#endif
			seq_num++;

			handshake_done = 1;
			secParam->client_write_IV = client_write_IV;
			secParam->server_write_IV = server_write_IV;
			secParam->client_write_key = client_write_key;
			secParam->server_write_key = server_write_key;
			connection->securityParameters = secParam;
			connection->conn = client_conn;
			tls_event = process_alloc_event();
			tls_flags = TLS_CONNECTED;
			process_post(PROCESS_BROADCAST, tls_event, (void*)connection);
			expected_message = APPLICATION_DATA;
			break;
		}
	} else {
		error(2, result);
	}
}

static void response_to_server_messages(uint8_t result) {
	if (result == 1) {

		char finished_clear[16];
		char nonce[12];
		char additional_data[13];
		switch(expected_message){
		case SERVER_HELLO:
			/*
			 * generate premaster secret
			 * RFC4279 section 2
			 */
#if MMEM2
			if(mmem_alloc(&mmem, 2*strlen(psk)+4)==0){
				error(2, 80);
				return;
			}
			premaster_secret = (char*)MMEM_PTR(&mmem);
#else
			if(!(premaster_secret = (char*)malloc(2*strlen(psk)+4))){
				error(2,80);
				return;
			}
#endif
			generate_premaster_secret(premaster_secret);
			generate_master_secret();
#if MMEM2
			mmem_free(&mmem);
#else
			free(premaster_secret);
#endif
			expected_message = SERVER_HELLO_DONE;
			break;
		case SERVER_HELLO_DONE:
			/*send ClientKeyExchange + ChangeCipherSuite + Finished
			clientKeyExchange has length psk_identity_length+11
			changeCipherSpec has length 6
			Finished has length 32*/
#if MMEM2
			if(mmem_alloc(&mmem, psk_identity_length+11+6+37)==0){
				error(2, 80);
				return;
			}
			buffer = (char*)MMEM_PTR(&mmem);
#else
			if (!(buffer = (char*) malloc(psk_identity_length+11 + 6 + 37))) {
				error(2,80);
				return;
			}
#endif
			create_client_key_exchange(buffer, psk_identity, psk_identity_length);
			sha256_update(&ctx, (unsigned char*)buffer+5, psk_identity_length+6);
			create_change_cipher_spec(buffer, psk_identity_length+11);
			//copy a sha256 context so that it can be used later for verifying the hash received from the server
			sha256_ctx ctxCopy = ctx;
			//encrypt the hash of all previous messages of the handshake!
			sha256_final(&ctx, (unsigned char*)handshake_hash);

			finished_clear[0] = 0x14; //msg_type = finished
			finished_clear[1] = 0x00; finished_clear[2] = 0x00; finished_clear[3] = 0x0c; //length
			PRF(finished_clear+4, master_secret, 48, "client finished", handshake_hash, 32, 12);
			//memcpy(finished_clear+4, PRF(master_secret, 48, "client finished", handshake_hash, 32, 12), 12);

			//generate keying material
			generate_keying_material();


			seq_num = 0;
			memcpy(nonce, client_write_IV, 4);
			memcpy(nonce+4, &seq_num, 8);
			memcpy(additional_data, &seq_num, 8);
			char type = 0x16; //handshake
			memcpy(additional_data+8, &type ,1);
			char version[2] = {0x03, 0x03}; //version 3.3
			memcpy(additional_data+9, version, 2);
			uint16_t length = 16; //length of the finished record
			memcpy(additional_data+11, &length, 2);

			if(!encrypt(buffer, psk_identity_length+6+11+13, client_write_key, nonce, finished_clear, 16, additional_data)){
#if MMEM2
				mmem_free(&mmem);
#else
				free(buffer);
#endif
				error(2,80);
				return;
			}

			sha256_update(&ctxCopy, (unsigned char*)buffer+6+11+13, 24);
			sha256_final(&ctxCopy, (unsigned char*)handshake_hash); //now handshake_hash has everything including the just sent finished message

			create_finished(buffer, psk_identity_length+11+6, seq_num, "");
			tcp_send(buffer, psk_identity_length+54);
#if MMEM2
			mmem_free(&mmem);
#else
			free(buffer);
#endif
			seq_num++;
			expected_message = CHANGE_CIPHER_SPEC;
			break;
		case CHANGE_CIPHER_SPEC:
			expected_message = FINISHED;
			break;
		case FINISHED:
			handshake_done = 1;

			secParam->client_write_IV = client_write_IV;
			secParam->server_write_IV = server_write_IV;
			secParam->client_write_key = client_write_key;
			secParam->server_write_key = server_write_key;

			connection->securityParameters = secParam;
			connection->conn = client_conn;
			tls_event = process_alloc_event();
			tls_flags = TLS_CONNECTED;
			process_post(PROCESS_BROADCAST, tls_event, (void*)connection);
			expected_message = APPLICATION_DATA;
			break;
		}
	} else {
		error(2, result);
	}
}
static int act_on_full_message(char* input, int msg_length, int offset){
	if (alert_received){
		alert_received = 0;
		if (input[offset+1] == 0){
			error(1,0);
			return 0;
		} else {
			if (server) num_connected--;
			state = READY;
			recv_length = 0;
			sha256_init(&ctx);
			send_error = 1;
			return 0;
		}
	}
	if (expected_message==APPLICATION_DATA){
		char nonce[12];
		char additional_data[13];
		if (server) memcpy(nonce, client_write_IV, 4);
		else memcpy(nonce, server_write_IV, 4);
		memcpy(nonce+4, input+offset, 8);
		memcpy(additional_data, input+offset, 8);
		char type = 0x17; //application data
		memcpy(additional_data+8, &type ,1);
		char version[2] = {0x03, 0x03}; //version 3.3
		memcpy(additional_data+9, version, 2);
		uint16_t length = msg_length-16; //length of the data
		memcpy(additional_data+11, &length, 2);
#if MMEM2
		mmem_free(&datammem);
		if(mmem_alloc(&datammem, msg_length - 16)==0){
			error(2, 80);
			return 0;
		}
		tls_appdata = (char*)MMEM_PTR(&datammem);

#else
		if(!(tls_appdata = (char*)malloc(msg_length-16))){
			error(2,80);
			return 0;
		}
#endif
		if (server) {
			if(!decrypt(tls_appdata, 0, client_write_key, nonce, input+offset+8, msg_length-8, additional_data)){
#if MMEM2
				mmem_free(&datammem);
#else
				free(tls_appdata);
#endif
				error(2,20);
				return 0;
			}
		}
		else {
			if(!decrypt(tls_appdata, 0, server_write_key, nonce, input+offset+8, msg_length-8, additional_data)){
#if MMEM2
				mmem_free(&datammem);
#else
				free(tls_appdata);
#endif
				error(2,20);
				return 0;
			}
		}
		tls_applen = msg_length - 16;
		tls_flags = TLS_NEWDATA;
		process_post(PROCESS_BROADCAST, tls_event, NULL);
		return 1;
	}
	if (server) {
		uint8_t result = process_client_messages(input,
				msg_length, offset, expected_message);
		if(expected_message == CLIENT_HELLO && result == 1){
			//save client_random
			memcpy(client_random, input+offset+6, 32);
		}
		if(expected_message == CLIENT_KEY_EXCHANGE && result == 1){
			psk_identity_length = (input[offset+4]<<8)+input[offset+5];
			memcpy(psk_identity, input+offset+6, psk_identity_length);
		}

		if (result == 1 && expected_message == FINISHED){ //need to verify the finished message
			char nonce[12];
			char additional_data[13];
			memcpy(nonce, client_write_IV, 4);
			memcpy(nonce+4, input+offset, 8);
			memcpy(additional_data, input+offset, 8);
			char type = 0x16; //handshake
			memcpy(additional_data+8, &type ,1);
			char version[2] = {0x03, 0x03}; //version 3.3
			memcpy(additional_data+9, version, 2);
			uint16_t length = 16; //length of the finished record
			memcpy(additional_data+11, &length, 2);
			char* finished_clear;
#if MMEM2
			if(mmem_alloc(&mmem, msg_length - 16)==0){
				error(2, 80);
				return 0;
			}
			finished_clear = (char*)MMEM_PTR(&mmem);

#else
			if(!(finished_clear = (char*)malloc(msg_length-16))){
				error(2,80);
				return 0;
			}
#endif
			if(!decrypt(finished_clear, 0, client_write_key, nonce, input+offset+8, msg_length-8, additional_data)){
#if MMEM2
				mmem_free(&mmem);
#else
				free(finished_clear);
#endif
				error(2,20);
				return 0;
			}
			sha256_ctx ctxCopy = ctx;
			sha256_final(&ctxCopy, (unsigned char*)handshake_hash);

			if (check_finished_correctness(finished_clear)!=1){
				error(2,40);
#if MMEM2
				mmem_free(&mmem);
#else
				free(finished_clear);
#endif
				return 0;
			}
#if MMEM2
			mmem_free(&mmem);
#else
			free(finished_clear);
#endif
		}
		if (result == 1 && expected_message!=CHANGE_CIPHER_SPEC) { //save incoming message to all_messages, will be used in Finished
			sha256_update(&ctx, (unsigned char*)input+offset, msg_length);
		}
		response_to_client_messages(result);
		if (result!=1) return 0;
	} else {
		uint8_t result = process_server_messages(input,
				msg_length, offset, expected_message);
		if(expected_message == SERVER_HELLO && result == 1){
			//save server_random
			memcpy(server_random, input+offset+6, 32);
		}
		if(result == 1 && !(expected_message==CHANGE_CIPHER_SPEC || expected_message == FINISHED)){
			sha256_update(&ctx, (unsigned char*)input+offset, msg_length);
		}
		if (result == 1 && expected_message == FINISHED){
			char nonce[12];
			char additional_data[13];
			memcpy(nonce, server_write_IV, 4);
			memcpy(nonce+4, input+offset, 8);
			memcpy(additional_data, input+offset, 8);
			char type = 0x16; //handshake
			memcpy(additional_data+8, &type ,1);
			char version[2] = {0x03, 0x03}; //version 3.3
			memcpy(additional_data+9, version, 2);
			uint16_t length = 16; //length of the finished record
			memcpy(additional_data+11, &length, 2);
			char* finished_clear;
#if MMEM2
			if(mmem_alloc(&mmem, msg_length - 16)==0){
				error(2, 80);
				return 0;
			}
			finished_clear = (char*)MMEM_PTR(&mmem);

#else
			if(!(finished_clear = (char*)malloc(msg_length-16))){
				error(2,80);
				return 0;
			}
#endif
			if(!decrypt(finished_clear, 0, server_write_key, nonce, input+offset+8, msg_length-8, additional_data)){
#if MMEM2
				mmem_free(&mmem);
#else
				free(finished_clear);
#endif
				error(2,20);
				return 0;
			}
			if (check_finished_correctness(finished_clear)!=1){
				error(2,40);
#if MMEM2
				mmem_free(&mmem);
#else
				free(finished_clear);
#endif
				return 0;
			}
#if MMEM2
			mmem_free(&mmem);
#else
			free(finished_clear);
#endif
		}
		response_to_server_messages(result);
		if (result!=1)return 0;
	}
	return 1;
}

/***************************************************************/
/*                      Handler functions                      */
/***************************************************************/
static void process_input(char* input, int input_length){
	uint8_t i, j;
	switch (state) {
	case RECV_MSG: //we are in this state when the message is arbitrary fragmented
		if (recv_length + input_length >= msg_length) { //we have all we need plus maybe more
			j = recv_length;
			for (i = 0; j < msg_length; i++) {
				buffer[j++] = input[i];
			}
			if (act_on_full_message(buffer, msg_length, 0)!=1) return;
#if MMEM2
			mmem_free(&process_mmem);
#else
			free(buffer);
#endif
			state = READY;
			if (input_length>i) process_input(input+i, input_length-i);
		} else {
			j = recv_length;
			for (i = 0; i < input_length; i++) {
				buffer[j++] = input[i];
			}
			recv_length = j; //still didn't get the whole message
			return;

		}
		break;
	case RECV_HEADER:
		if ((input_length + recv_length) < 5) {
			//still didn't get the header...jeez
			for (i = 0; i < input_length; i++) {
				buffer[recv_length + i] = input[i];
			}
			recv_length += input_length;
			return;
		} else {
			for (i = 0; recv_length < 5; i++) {
				buffer[recv_length + i] = input[i];
				recv_length++;
			}
			j = i;
			msg_length = (buffer[3] << 8) + (buffer[4]);
#if MMEM2
			mmem_free(&process_mmem);
#else
			free(buffer);
#endif
			if (input_length - i < msg_length) { //message fragmented
#if MMEM2
				if (mmem_alloc(&process_mmem, msg_length) == 0){
					error(2, 80);
					return;
				}
				buffer = (char*)MMEM_PTR(&process_mmem);
#else
				if (!(buffer = (char*) malloc(msg_length))) {
					//create fatal internal error message
					error(2, 80);
					return;
				} //allocating enough space for the whole message
#endif
				for (; i < input_length; i++) {
					buffer[i - j] = input[i]; //copy the message to the buffer
				}
				recv_length = i - j;
				state = RECV_MSG;
				return;
			} else {
				//ok i have the whole message (or more), pass it to a function that will parse it
				//also give an offset j
				if (act_on_full_message(input, msg_length, j)!=1) return;
				if (input_length - j > msg_length) {
					state=READY;
					process_input(input+j+msg_length, input_length-j-msg_length);
				}
			}
		}
		break;
	case READY: //initial state after TCP connection was established
		if (input[0] == 0x15){
			alert_received = 1;
		} else {
			if (expected_message!=CHANGE_CIPHER_SPEC && expected_message!=APPLICATION_DATA && input[0] != 0x16) { //have to get a handshake message first (type 22)
				//unexpected message error (fatal)
				error(2, 10);
				return;
			}
			if (expected_message == CHANGE_CIPHER_SPEC && input[0] != 0x14) {
				//unexpected message error (fatal)
				error(2, 10);
				return;
			}
			if (expected_message == APPLICATION_DATA && input[0] != 0x17){
				error(2,10);
				return;
			}
		}
		if (input_length < 5) { //didn't get enough to see how big the message is
			state = RECV_HEADER;
			//store what we received in a buffer
#if MMEM2
			if(mmem_alloc(&process_mmem, 5)==0){
				error(2, 80);
				return;
			}
			buffer = (char*)MMEM_PTR(&process_mmem);
#else
			if (!(buffer = (char*) malloc(5))) {
				//create fatal internal error message
				error(2, 80);
				return;
			}
#endif
			for (i = 0; i < input_length; i++) {
				buffer[i] = input[i];
			}
			recv_length = input_length;
			return;
		}
		msg_length = (input[3] << 8) + (input[4]);
		if (input_length < 5 + msg_length) {
			//received message doesn't contain the complete sent message (was fragmented)
#if MMEM2
			if(mmem_alloc(&process_mmem, msg_length)==0){
				raven_lcd_show_text("sadness");
				error(2, 80);
				return;
			}
			buffer = (char*)MMEM_PTR(&process_mmem);
#else
			if (!(buffer = (char*) malloc(msg_length))) {
				//create fatal internal error message
				raven_lcd_show_text("sadness");
				error(2,80);
				return;
			}
#endif
			for (i = 5; i < input_length; i++) {
				buffer[i - 5] = input[i];
			}
			recv_length = input_length - 5;
			state = RECV_MSG;
			return;
		} else {
			if (act_on_full_message(input, msg_length, 5)!=1) return;

			if (input_length > 5 + msg_length) {
				//we have more to process, pass it back to the function
				process_input(input+msg_length+5, input_length-msg_length-5);
			}
		}
		break;
	}
}


static void handshake_event_handler(process_event_t ev, process_data_t data) {
	if (ev == tcpip_event) {
		if (uip_connected()) {
			if (server) {
				client_conn = uip_conn;
				if (num_connected == MAX_CONNECTIONS) {
					//send an internal_error alert (fatal)
					tcp_send(internal_error, 7);
#if MMEM2
					mmem_free(&process_mmem);
#else
					free(buffer);
#endif
					uip_close();
					return;
				}
				raven_lcd_show_text("got conn");
				state = READY;
			} else {
				raven_lcd_show_text("conn");
				tcp_send(buffer, 50);
#if MMEM2
				mmem_free(&process_mmem);
#else
				free(buffer);
#endif
			}
		} else if (uip_newdata()) {
			process_input((char*)uip_appdata, uip_datalen());
		} else if (uip_closed()){
			if (server) {
				num_connected--;
				expected_message = SERVER_HELLO;
			}
			state = READY;
			expected_message = CLIENT_HELLO;
			recv_length = 0;
#if MMEM2
			mmem_free(&datammem);
			mmem_free(&sec_mmem);
			mmem_free(&conn_mmem);
#else
			free(secParam);
			free(connection);
#endif
		}
	}
}
/***************************************************************/
/*                         Processes                           */
/***************************************************************/
PROCESS_THREAD(tls_client_handshake_process, ev, data) {
PROCESS_BEGIN();

	Data* d = (struct Data*) data;
	uip_ipaddr_t* addr = d->addr;
	uint16_t port = d->port;
	client_conn = tcp_connect(addr, UIP_HTONS(port), NULL);
	raven_lcd_show_text("trying");
	sha256_init(&ctx);
	/*Create Client Hello message*/
#if MMEM2
	if (mmem_alloc(&process_mmem,50)==1){
		buffer = (char*)MMEM_PTR(&process_mmem);
#else
	if ((buffer = (char*) malloc(50))) {
#endif
		create_client_hello(buffer);
		//save client_random
		memcpy(client_random,buffer+11,32);
		//update the hash of all handshake messages
		sha256_update(&ctx, (unsigned char*)buffer+5, 45);
		/*  done  */
		while (1) {
			PROCESS_YIELD();
			if (send_error){
				uip_close();
				send_error = 0;
			}
			handshake_event_handler(ev, data);
		}
	}
PROCESS_END();
}

PROCESS_THREAD(tls_server_listen, ev, data) {
	PROCESS_BEGIN();
	uint16_t port = *(uint16_t*) data;
	tcp_listen(UIP_HTONS(port));
	sha256_init(&ctx); //initialize the context for the hashing function
	while (1) {
		PROCESS_YIELD();
		if (send_error){
			uip_close();
			send_error = 0;
		}
		handshake_event_handler(ev, data);
	}
	PROCESS_END();
}
