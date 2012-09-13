#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include <avr/io.h>
#include "raven-lcd.h"
#include <string.h>
#include "hmac_sha2.h"
#include "aes_ccm.h"
#include "lib/mmem.h"
#include "util.h"
#include <stdio.h>
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
#define APPLICATION_DATA 0x07
#define TLS_CONNECTED 1
#define TLS_NEWDATA 2
#define TLS_CLOSED 4
#define TLS_OUTDATA 8
static struct etimer et;
PROCESS(udp_server_process, "UDP server process");
PROCESS(server_process, "server process");
AUTOSTART_PROCESSES(&udp_server_process);
/*---------------------------------------------------------------------------*/

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
static char server_random[32];
static char client_random[32];
static char handshake_hash[32];
static uint16_t msg_length = 0;
static int more_to_send = 0;
static int connected = 0;
static struct process* cur_process;
static uint8_t tls_flags;
static process_event_t tls_event;
static process_event_t send_event;
static uint8_t server = 0;
static uint8_t expected_message;
static uint8_t max_connections = 0;
static Connection* connection;
static SecurityParameters* secParam;
static int message = 0;
static int acked = 0;
static sha256_ctx ctx;
static uint8_t send_error = 0;
static struct uip_conn *conn;
static struct process* calling_process;
static struct mmem mmem;
static struct mmem mmem2;
static struct mmem datammem;
static struct mmem process_mmem;
static struct mmem conn_mmem;
static struct mmem sec_mmem;
static char* premaster_secret;
static char master_secret[48];
static char client_write_key[16];
static char client_write_IV[4];
static char server_write_key[16];
static char server_write_IV[4];
static uint8_t handshake_done = 0;
static uint8_t alert_received = 0;
static uint8_t wait_for_ack = 0;
static struct uip_conn *client_conn;
static char* buffer;
static uint8_t num_connected = 0;
static char internal_error[] = { (char) 0x15, (char) 0x03, (char) 0x03,
		(char) 0x00, (char) 0x02, (char) 0x02, (char) 0x50 };
static uint64 seq_num;
static uint8_t recv_length = 0;
static uint8_t state = READY;
static char psk[32] = "abcdefghijklmnopqrstuvwxyz123456";
static char* psk_identity = "thisisme";
static uint16_t psk_identity_length = 8;
static char* tls_appdata;
static int tls_applen;
//static char buffer1[] = {(char)0x14, (char)0x03, (char)0x03, (char)0x00, (char)0x01, (char)0x01, (char)0x16, (char)0x03, (char)0x03, (char)0x00, (char)0x20, (char)0x00, (char)0x00, (char)0x00, (char)0x00, (char)0x00, (char)0x00, (char)0x00, (char)0x00, (char)0x8b, (char)0x3d, (char)0x05, (char)0x89, (char)0x3f, (char)0x7e, (char)0x0b, (char)0x3e, (char)0xfc, (char)0x9f, (char)0x1a, (char)0x3c, (char)0x4a, (char)0xc4, (char)0xa2, (char)0xe0, (char)0x09, (char)0x44, (char)0xdd, (char)0x81, (char)0x36, (char)0xbd, (char)0x21, (char)0x11};
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

static void tcp_send(char* toSend, int length){
	uip_send(toSend, length);
	tcpip_poll_tcp(client_conn);
}


static void error(uint8_t level, uint8_t type){
	if (server) num_connected--;
	state = READY;
	recv_length = 0;
	sha256_init(&ctx);
	if (type == 80){
		if (server) uip_send(internal_error, 7);
		else tcp_send(internal_error, 7);
	}
	else {
		if(mmem_alloc(&mmem, 7)==0){
			if (server) uip_send(internal_error, 7);
			else tcp_send(internal_error, 7);
		} else {
			buffer = (char*)MMEM_PTR(&mmem);
			create_alert(buffer, level, type);
			if (server) uip_send(buffer, 7);
			else tcp_send(buffer, 7);
			mmem_free(&mmem);
		}
	}
	send_error = 1;
}
int TLS_Listen(uint16_t port, uint8_t max_conn) {
	if (max_conn > MAX_CONNECTIONS) {
		return -1;
	}
	server = 1;
	expected_message = CLIENT_HELLO;
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
	process_start(&server_process, (void*) &port);
	return 0;
}
int P_SHA256(char* output, unsigned char* key, int key_length, unsigned char* seed, int seed_length, int length){
	int tmp = length % 32 == 0 ? length/32 : length/32 + 1;
	char* out;
	//struct mmem mmem;
	if (mmem_alloc(&mmem2, 32*tmp)==0){
		return -1;
	}
	out = (char*)MMEM_PTR(&mmem2);
	memset(out, 0, 32*tmp);
	if (!out) return -1;
	char A[32];
	int i = 0;
	int output_length = 0;
	hmac_sha256(key, key_length,seed,seed_length, (unsigned char*)A, 32  );
	i = 0;
	while (1){
		if (output_length>32*i){
			char tmpOutput[32];
			char newSeed[32+seed_length];
			memcpy(newSeed, A, 32);
			memcpy(newSeed+32, seed, seed_length);
			hmac_sha256(key, key_length,(unsigned char*)newSeed, 32+seed_length, (unsigned char*)tmpOutput, 32 );
			hmac_sha256(key, key_length, (unsigned char*)A, 32, (unsigned char*)A, 32);
			memcpy(out+output_length, tmpOutput, 32);
			output_length+=32;
			i++;
		} else {
			break;
		}
	}
	memcpy(output, out, length);
	mmem_free(&mmem2);
	return 1;

}

int PRF(char* output, char* secret, int secret_length, char* label, char* seed, int seed_length, int size){
	char labelSeed[strlen(label)+seed_length];
	memcpy(labelSeed, label, strlen(label));
	memcpy(labelSeed+strlen(label), seed, seed_length);
	return P_SHA256(output, (unsigned char*) secret, secret_length, (unsigned char*)labelSeed, strlen(label)+seed_length, size );
}
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

			if(mmem_alloc(&mmem, 56)==0){
				error(2, 80);
				return;
			}
			buffer = (char*)MMEM_PTR(&mmem);
			create_server_hello(buffer);
			//save server_random
			memcpy(server_random,buffer+11,32);
			//update the hash
			sha256_update(&ctx, (unsigned char*)buffer+5, 42);
			sha256_update(&ctx, (unsigned char*)buffer+52, 4);
			expected_message = CLIENT_KEY_EXCHANGE;
			uip_send(buffer, 56);

			mmem_free(&mmem);
			break;
		case CLIENT_KEY_EXCHANGE:
			//lookup PSK based on the psk_identity
			//TODO
			//generate premaster secret

			if(mmem_alloc(&mmem, 2*strlen(psk)+4)==0){
				error(2, 80);
				return;
			}
			premaster_secret = (char*)MMEM_PTR(&mmem);
			generate_premaster_secret(premaster_secret);
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
			if(mmem_alloc(&mmem, 6+37)==0){
					error(2, 80);
					return;
			}
			buffer = (char*)MMEM_PTR(&mmem);
			create_change_cipher_spec(buffer, 0);
			//encrypt the hash of all previous messages of the handshake!
			sha256_final(&ctx, (unsigned char*)handshake_hash);
			finished_clear[0] = 0x14; //msg_type = finished
			finished_clear[1] = 0x00; finished_clear[2] = 0x00; finished_clear[3] = 0x0c; //length
			PRF(finished_clear+4, master_secret, 48, "server finished", handshake_hash, 32, 12);
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

				mmem_free(&mmem);
				error(2, 80);
				return;
			}
			create_finished(buffer, 6, seq_num,"");

			wait_for_ack = 1;
			tcp_send(buffer, 6+37);
			//tcp_send("asdf",4);
			mmem_free(&mmem);
			seq_num++;
			more_to_send = 1;
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

		mmem_free(&datammem);
		if(mmem_alloc(&datammem, msg_length - 16)==0){
			error(2, 80);
			return 0;
		}
		tls_appdata = (char*)MMEM_PTR(&datammem);

		if (server) {
			if(!decrypt(tls_appdata, 0, client_write_key, nonce, input+offset+8, msg_length-8, additional_data)){

				mmem_free(&datammem);
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
			if(mmem_alloc(&mmem, msg_length - 16)==0){
				error(2, 80);
				return 0;
			}
			finished_clear = (char*)MMEM_PTR(&mmem);
			if(!decrypt(finished_clear, 0, client_write_key, nonce, input+offset+8, msg_length-8, additional_data)){
				mmem_free(&mmem);
				error(2,20);
				return 0;
			}
			sha256_ctx ctxCopy = ctx;
			sha256_final(&ctxCopy, (unsigned char*)handshake_hash);
			if (check_finished_correctness(finished_clear)!=1){
				error(2,40);

				mmem_free(&mmem);
				return 0;
			}
			mmem_free(&mmem);
		}
		if (result == 1 && expected_message!=CHANGE_CIPHER_SPEC) { //save incoming message to all_messages, will be used in Finished
			sha256_update(&ctx, (unsigned char*)input+offset, msg_length);
		}
		response_to_client_messages(result);
		if (result!=1) return 0;
	}
	return 1;
}

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

			mmem_free(&process_mmem);
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
			msg_length = ((unsigned char)buffer[3] << 8) + ((unsigned char)buffer[4]);

			mmem_free(&process_mmem);
			if (input_length - i < msg_length) { //message fragmented

				if (mmem_alloc(&process_mmem, msg_length) == 0){
					error(2, 80);
					return;
				}
				buffer = (char*)MMEM_PTR(&process_mmem);
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

			if(mmem_alloc(&process_mmem, 5)==0){
				error(2, 80);
				return;
			}
			buffer = (char*)MMEM_PTR(&process_mmem);
			for (i = 0; i < input_length; i++) {
				buffer[i] = input[i];
			}
			recv_length = input_length;
			return;
		}

		msg_length = ((unsigned char)input[3] << 8) + ((unsigned char)input[4]);
		if (input_length < 5 + msg_length) {
			//received message doesn't contain the complete sent message (was fragmented)

			if(mmem_alloc(&process_mmem, msg_length)==0){
				error(2, 80);
				return;
			}
			buffer = (char*)MMEM_PTR(&process_mmem);
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



static void
tcpip_handler(process_event_t ev, process_data_t data)
{
	if(ev == tcpip_event){
		if (acked && uip_acked()){
		//	raven_lcd_show_text("yes");
			acked = 0;
			connected = 1;
			tls_event = process_alloc_event();
			process_post(calling_process, tls_event, NULL);
		} else
		if (uip_connected()){
			message = 1;
			conn = uip_conn;
		} else if(uip_newdata()) {
			((char *)uip_appdata)[uip_datalen()] = 0;
			raven_lcd_show_text((char*)uip_appdata);
			if (message == 1){
				uip_send("server hello", 12);
				message = 2;
			} else if (message == 2){
				uip_send("change cipher spec finished", 27);
				message = 3;
			//	more_to_send = 1;
				acked = 1;
			}
		}
	} else if (ev == send_event){
		raven_lcd_show_text("here");

		uip_send("connected", 9);
		tcpip_poll_tcp(conn);
	}
}
static void tls_handler(process_event_t ev, process_data_t data){
	if (ev == tls_event){

			//raven_lcd_show_text("connected");
		char* toWrite = "connected";
			send_event = process_alloc_event();
			process_post(cur_process, send_event, (void*)toWrite);

	}
}


static void handshake_event_handler(process_event_t ev, process_data_t data) {
	if (ev == tcpip_event) {
		if (wait_for_ack && uip_acked()){
			handshake_done = 1;
			secParam->client_write_IV = client_write_IV;
			secParam->server_write_IV = server_write_IV;
			secParam->client_write_key = client_write_key;
			secParam->server_write_key = server_write_key;
			connection->securityParameters = secParam;
			connection->conn = client_conn;
			tls_event = process_alloc_event();
			tls_flags = TLS_CONNECTED;
			process_post(calling_process, tls_event, (void*)connection);
			expected_message = APPLICATION_DATA;
			wait_for_ack = 0;
		}else
		if (uip_connected()) {
			message = 1;
				client_conn = uip_conn;
				if (num_connected == MAX_CONNECTIONS) {
					//send an internal_error alert (fatal)
					uip_send(internal_error, 7);

					mmem_free(&process_mmem);
					uip_close();
					return;
				}
				state = READY;

		} else if (uip_newdata()) {
		/*	((char *)uip_appdata)[uip_datalen()] = 0;
			raven_lcd_show_text((char*)uip_appdata);
			if (message == 1){
				uip_send("server hello", 12);
				message = 2;
			} else if (message == 2){
				uip_send("change cipher spec finished", 27);
				message = 3;
				//	more_to_send = 1;
				wait_for_ack = 1;
			}*/
				process_input((char*)uip_appdata, uip_datalen());
		}
	} else if (ev == send_event){

		char* toWrite = (char*)data;
		raven_lcd_show_text(toWrite);
		int length = strlen(toWrite);
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
		if(mmem_alloc(&mmem, length+21)==0){
			error(2, 80);
			return;
		}
		encrypted = (char*)MMEM_PTR(&mmem);
		if (server) {
			if(!encrypt(encrypted, 13, server_write_key, nonce, toWrite, length, additional_data)) {
				mmem_free(&mmem);
				return;
			}
		}
		else {
			if(!encrypt(encrypted, 13, client_write_key, nonce, toWrite, length, additional_data)) {
				mmem_free(&mmem);
				return;
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
		mmem_free(&mmem);
		//tcp_send("connected", 9);
	}
}
PROCESS_THREAD(udp_server_process, ev, data)
{

  PROCESS_BEGIN();

  /*etimer_set(&et, CLOCK_CONF_SECOND*3);
  PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);
  calling_process = PROCESS_CURRENT();
  process_start(&server_process, NULL);
  while(1){
	  PROCESS_YIELD();
	  tls_handler(ev, data);
  }*/
  TLS_Listen(443,1);
  	while(1){
  		PROCESS_YIELD();
  		tls_handler(ev, data);
  	}
  PROCESS_END();
}

PROCESS_THREAD(server_process, ev, data)
{
	PROCESS_BEGIN();
	/*tcp_listen(UIP_HTONS(3000));
	  etimer_set(&et, CLOCK_CONF_SECOND);

	  while(1) {

	  	PROCESS_YIELD();

	  	tcpip_handler(ev, data);

	  }*/
	cur_process = PROCESS_CURRENT();
		uint16_t port = *(uint16_t*) data;
		tcp_listen(UIP_HTONS(port));
		sha256_init(&ctx); //initialize the context for the hashing function
		while (1) {
			PROCESS_YIELD();
			if (send_error){
				uip_close();
				send_error = 0;
			} else
			handshake_event_handler(ev, data);
				//tcpip_handler(ev, data);
		}
	  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
