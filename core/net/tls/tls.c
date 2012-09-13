#include "tls.h"
#include "ntpd.h"
#include "random.h"
#include "cfs-coffee.h"
#include "hmac_sha2.h"
#include "aes_ccm.h"
#include "string.h"
#include "lib/mmem.h"
/***************************************************************/
/*                   Process definitions                       */
/***************************************************************/
PROCESS(tls_client_handshake_process, "1");
PROCESS(tls_server_listen, "2");

/***************************************************************/
/*                     Static variables                        */
/***************************************************************/
static struct uip_conn *client_conn;
static struct process* cur_process;
static struct process* calling_process;
static uint8_t num_connected = 0;
static uint8_t max_connections = 0;
static char* buffer;
static char* record_buffer;
static unsigned long message_length = 0;
static unsigned long message_recv_length = 0;
static uint16_t record_length = 0;
static uint16_t recv_length = 0;
static uint16_t overall_sent_data = 65535;
static uint8_t state = READY; //internal state for message processing, one of READY, RECV_HEADER, RECV_MSG
static uint8_t record_state = RECORD_READY;
static uint8_t expected_message; //specifies which message should come next during the handshake
static uint8_t send_error = 0;
static uint8_t handshake_done = 0;
static uint8_t server = 0;
static uint8_t alert_received = 0;
static uint8_t wait_for_ack = 0;
static uint8_t first_data = 1;
static uint8_t first_data_sent = 1;
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
static char psk[33] = "abcdefghijklmnopqrstuvwxyz123456\0";
static char* psk_identity = "thisisme";
static uint16_t psk_identity_length = 8;
static Connection* connection;
static SecurityParameters* secParam;
static struct mmem mmem;
static struct mmem pskmmem;
static struct mmem datammem;
static struct mmem process_mmem;
static struct mmem record_mmem;
static struct mmem conn_mmem;
static struct mmem sec_mmem;
static char internal_error[] = { (char) 0x15, (char) 0x03, (char) 0x03,
		(char) 0x00, (char) 0x02, (char) 0x02, (char) 0x50 };



static void tcp_send(char* toSend, int length){
	uip_send(toSend, length);
	tcpip_poll_tcp(client_conn);
}


static void error(uint8_t level, uint8_t type){
	if (server) num_connected--;
	state = READY;
	record_state = RECORD_READY;
	recv_length = 0;
	message_recv_length = 0;
	sha256_init(&ctx);
	if(!first_data){
		mmem_free(&datammem);
	}
	first_data =1;
	if (type == 80){
		tcp_send(internal_error, 7);
	}
	else {
		if(mmem_alloc(&mmem, 7)==0){
			tcp_send(internal_error, 7);
		} else {
			buffer = (char*)MMEM_PTR(&mmem);
			create_alert(buffer, level, type);
			tcp_send(buffer, 7);
			mmem_free(&mmem);
		}
	}
	send_error = 1;
}

static void rehandshake(){
	overall_sent_data = 0;
	if(!first_data_sent)mmem_free(&mmem);
	first_data_sent = 1;
	if (!first_data)mmem_free(&datammem);
	first_data = 1;
	sha256_init(&ctx);
	if (server){
		if (mmem_alloc(&mmem,9)==0){
			error(2,80);
			return;
		}
		buffer = (char*)MMEM_PTR(&mmem);
		create_hello_request(buffer);
		tcp_send(buffer, 9);
		expected_message = CLIENT_HELLO;
		handshake_done = 0;
		mmem_free(&mmem);
	} else {

		handshake_done = 0;
		if (mmem_alloc(&mmem, 50)==0){
			error(2,80);
			return;
		}
		buffer = (char*)MMEM_PTR(&mmem);
		create_client_hello(buffer);
		uint8_t i;
		for (i = 0; i < 32; i++){
			client_random[i] = buffer[11+i];
		}
		sha256_update(&ctx, (unsigned char*)buffer+5, 45);
		tcp_send(buffer, 50);
		mmem_free(&mmem);
		expected_message = SERVER_HELLO;
	}
	tls_flags = TLS_REHANDSHAKE;
	tls_event = process_alloc_event();
	process_post(PROCESS_BROADCAST, tls_event, NULL);
}

/***************************************************************/
/*                          API Calls                          */
/***************************************************************/

void tls_connect(uip_ipaddr_t *ripaddr, uint16_t port) {

	server = 0;
	expected_message = SERVER_HELLO;
	Data data = { ripaddr, port };
	if(mmem_alloc(&sec_mmem, sizeof(SecurityParameters))==0){
		return;
	}
	secParam = (SecurityParameters*)MMEM_PTR(&sec_mmem);
	if(mmem_alloc(&conn_mmem, sizeof(Connection))==0){
		return;
	}
	connection = (Connection*)MMEM_PTR(&conn_mmem);
	process_start(&tls_client_handshake_process, (void*) &data);
}

int tls_listen(uint16_t port, uint8_t max_conn) {

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
	process_start(&tls_server_listen, (void*) &port);
	return 0;
}

int tls_write(Connection* conn, char* toWrite, int length){
	if (expected_message != APPLICATION_DATA){
		return -1;
	}
	if(overall_sent_data<length){
		rehandshake();
		return 0;
	}
	overall_sent_data-=length;
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
	if (!first_data_sent){
		mmem_free(&mmem);
	}
	first_data_sent = 0;
	if(mmem_alloc(&mmem, length+21)==0){
		error(2, 80);
		return -1;
	}
	encrypted = (char*)MMEM_PTR(&mmem);
	if (server) {
		if(!encrypt(encrypted+13, server_write_key, nonce, toWrite, length, additional_data)) {
			mmem_free(&mmem);
			return -1;
		}
	}
	else {
		if(!encrypt(encrypted+13, client_write_key, nonce, toWrite, length, additional_data)) {
			mmem_free(&mmem);
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
	mmem_free(&mmem);
	return 1;
}

void tls_close(Connection* conn){
	client_conn = conn->conn;
	error(1, 0);
	//FIXME alert is not being sent...
}

/***************************************************************/
/*                      Helper functions                       */
/***************************************************************/

static void generate_premaster_secret(char* ps, char* localpsk){
	uint16_t n = strlen(psk);
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

static int findpsk(int fd, char* psk_id){
	uint8_t pos = 0;
	uint8_t used = 0;
	char buf[4];
	cfs_seek(fd,pos,CFS_SEEK_SET);
	cfs_read(fd,buf,1);
	while(1){
		while(buf[0]!='<'){
			if(buf[0]=='\0') {
				if(used){
					return 0;
				}
				return -1;
			}
			pos++;
			cfs_seek(fd,pos,CFS_SEEK_SET);
			cfs_read(fd,buf,1);
		}
		pos++;
		cfs_seek(fd,pos,CFS_SEEK_SET);
		cfs_read(fd,buf,4);
		if(!strcmp(buf,"psk>")){
			used = 1;
			pos+=4; //jump over 'psk>'
			cfs_seek(fd,pos,CFS_SEEK_SET);
			cfs_read(fd, buf, 1);
			while(1){
				while(buf[0]!='<'){
					if(buf[0]=='\0') {
						if(used){
							return 0;
						}
						return -1;
					}
					pos++;
					cfs_seek(fd,pos,CFS_SEEK_SET);
					cfs_read(fd, buf, 1);
				}
				pos++;
				cfs_seek(fd,pos,CFS_SEEK_SET);
				cfs_read(fd,buf,4);
				if(!strcmp(buf,"psk-")){
					pos+=13;
					uint8_t id_pos = 0;
					uint8_t found = 1;
					cfs_seek(fd,pos,CFS_SEEK_SET);
					cfs_read(fd,buf,1);
					while(buf[0]!='<'){
						if(buf[0]!=psk_id[id_pos]){
							found = 0;
							break;
						}
						pos++;
						id_pos++;
						cfs_seek(fd,pos,CFS_SEEK_SET);
						cfs_read(fd,buf,1);
					}
					if(found){
						while(1){
							do{
								pos++;
								cfs_seek(fd,pos,CFS_SEEK_SET);
								cfs_read(fd,buf,1);
							}while(buf[0]!='<');
							pos++;
							cfs_seek(fd,pos,CFS_SEEK_SET);
							cfs_read(fd,buf,4);
							if(!strcmp(buf,"key>")){
								pos+=4;
								uint8_t key_start = pos;
								cfs_seek(fd,pos,CFS_SEEK_SET);
								cfs_read(fd,buf,1);
								while(buf[0]!='<'){
									pos++;
									cfs_seek(fd,pos,CFS_SEEK_SET);
									cfs_read(fd,buf,1);
								}
								if(mmem_alloc(&pskmmem,pos-key_start)==0){
									return -2;
								}
								char* p = (char*)MMEM_PTR(&pskmmem);
								cfs_seek(fd,key_start,CFS_SEEK_SET);
								cfs_read(fd,p,pos-key_start);
								return pos-key_start;
							}
						}
					}
				}
			}
		}
	}
	return -1;
}

static void response_to_client_messages(uint8_t result) {
	if (result == 1) {
		char finished_clear[16];
		char nonce[12];
		char additional_data[13];
		int fd;
		char* localpsk = psk;
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
			if ((fd=cfs_open("/config.xml",CFS_READ))<0){
				//no config found, using default (hardcoded) values for psk
				mmem_alloc(&pskmmem, 1); //dummy
			} else {
				int found = findpsk(fd, psk_identity );
				if(found == -1){
					//no psk list found, use default
					mmem_alloc(&pskmmem, 1);
				} else if(found == 0){
					//not a known psk_identity - deny access and send unknown_psk_identity alert
					error(2,115);
					return;
				} else if(found == -2){
					//run out of memory - internal error
					error(2,80);
					return;
				} else {
					//psk is stored at pskmmem
					localpsk = (char*)MMEM_PTR(&pskmmem);
				}
			}
			//generate premaster secret

			if(mmem_alloc(&mmem, 2*strlen(localpsk)+4)==0){
				error(2, 80);
				return;
			}
			premaster_secret = (char*)MMEM_PTR(&mmem);
			generate_premaster_secret(premaster_secret, localpsk);
			generate_master_secret();
			mmem_free(&pskmmem);
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
			if(!encrypt(buffer+6+13, server_write_key, nonce, finished_clear, 16, additional_data)){

				mmem_free(&mmem);
				error(2, 80);
				return;
			}
			create_finished(buffer, 6, seq_num,"");
			wait_for_ack = 1;
			tcp_send(buffer, 6+37);
			mmem_free(&mmem);
			seq_num++;
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
			if(mmem_alloc(&mmem, 2*strlen(psk)+4)==0){
				error(2, 80);
				return;
			}
			premaster_secret = (char*)MMEM_PTR(&mmem);
			generate_premaster_secret(premaster_secret, psk);
			generate_master_secret();

			mmem_free(&mmem);
			expected_message = SERVER_HELLO_DONE;
			break;
		case SERVER_HELLO_DONE:
			/*send ClientKeyExchange + ChangeCipherSuite + Finished
			clientKeyExchange has length psk_identity_length+11
			changeCipherSpec has length 6
			Finished has length 32*/

			if(mmem_alloc(&mmem, psk_identity_length+11+6+37)==0){
				error(2, 80);
				return;
			}
			buffer = (char*)MMEM_PTR(&mmem);
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

			if(!encrypt(buffer+psk_identity_length+6+11+13, client_write_key, nonce, finished_clear, 16, additional_data)){
				mmem_free(&mmem);
				error(2,80);
				return;
			}

			sha256_update(&ctxCopy, (unsigned char*)finished_clear, 16);
			sha256_final(&ctxCopy, (unsigned char*)handshake_hash); //now handshake_hash has everything including the just sent finished message

			create_finished(buffer, psk_identity_length+11+6, seq_num, "");
			tcp_send(buffer, psk_identity_length+54);
			mmem_free(&mmem);
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
/*
 * return 1 if all good
 * else return the alert type
 */
uint8_t process_server_messages(char* buffer, uint16_t msg_length, uint8_t offset, char expected_message) {
	switch(expected_message){
	uint16_t position;
	case SERVER_HELLO:
		position = offset;
		if (buffer[position++] != 0x03){ //TLS version has to be 1.2
			return 47;
		}
		if (buffer[position++] != 0x03){
			return 47;
		}
		position += 32; //skip random for now
		position += (buffer[position] + 1); //skip session id since we don't support it anyway (buffer[position] should always be 0)

		if (buffer[position++] != (char)((TLS_PSK_WITH_AES_128_CCM_8 >> 8) & 0xFF)){ //server has to return TLS_PSK_WITH_AES_128_CCM_8
			return 40;
		}
		if (buffer[position++] != (char)((TLS_PSK_WITH_AES_128_CCM_8) & 0xFF)){//otherwise it's a handshake_failure
			return 40;
		}
		if (buffer[position] != 0x00) //compression method has to be null
			return 40;
		break;
	case SERVER_HELLO_DONE:
		if (msg_length!=0) return 50;
		break;
	case CHANGE_CIPHER_SPEC:
		position = offset;
		if (buffer[position] != 0x01)
			return 50;
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
uint8_t process_client_messages(char* buffer, uint16_t msg_length, uint8_t offset, char expected_message) {
	uint16_t position;
	switch(expected_message){
	case CLIENT_HELLO:
		position = offset;
		if (buffer[position++] != 0x03)
			return 47;
		if (buffer[position++] != 0x03) //TLS version has to be 1.2
			return 47;
		position += 32; //skip random for now
		position += (buffer[position] + 1); //skip session id since we don't support it anyway
		uint16_t length = (buffer[position] << 8) + (buffer[position + 1]);
		position += 2;

		if (length > msg_length - position - offset|| length % 2 == 1){
			return 50;
		}
		uint8_t good = 0;
		while (length/2 > 0) {
			if ((buffer[position] == (char)(((TLS_PSK_WITH_AES_128_CCM_8 >> 8) & 0xFF)))
					&& (buffer[position + 1] == (char)((TLS_PSK_WITH_AES_128_CCM_8 & 0xFF)))) {
				good = 1;
				position += length;
				break;
			} else {
				length -= 2;
				position += 2;
			}
		}
		if (!good)
			return 40;
		length = buffer[position++];
		if (length > msg_length - position - offset){
			return 50;
		}
		good = 0;
		while (length > 0) {
			if (buffer[position] == 0x00) {
				good = 1;
				position += length;
				break;
			} else {
				length--;
				position++;
			}
		}
		if (!good)
			return 40;
		break;
	case CLIENT_KEY_EXCHANGE:
		position = offset;
		if (((buffer[position]<<8) + buffer[position+1]) != msg_length - 2)
			return 50;
		break;
	case CHANGE_CIPHER_SPEC:
		position = offset;
		if (buffer[position] != 0x01)
			return 50;
		break;
	case FINISHED:
		break;
	}
	return 1;

}

static int act_on_full_message(char* input, int msg_length, int offset){

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

		if (!first_data)mmem_free(&datammem);
		first_data = 0;
		if(mmem_alloc(&datammem, msg_length - 16)==0){
			error(2, 80);
			return 0;
		}
		tls_appdata = (char*)MMEM_PTR(&datammem);

		if (server) {
			if(!decrypt(tls_appdata, client_write_key, nonce, input+offset+8, msg_length-8, additional_data)){

				mmem_free(&datammem);
				error(2,20);
				return 0;
			}
		}
		else {
			if(!decrypt(tls_appdata, server_write_key, nonce, input+offset+8, msg_length-8, additional_data)){

				mmem_free(&datammem);
				error(2,20);
				return 0;
			}
		}
		tls_applen = msg_length - 16;
		tls_flags = TLS_NEWDATA;
		process_post(calling_process, tls_event, NULL);
		return 1;
	}
	if (server) {
		uint8_t result = process_client_messages(input,
				msg_length, offset, expected_message);
		if(expected_message == CLIENT_HELLO && result == 1){
			//save client_random
			memcpy(client_random, input+offset+2, 32);
		}
		if(expected_message == CLIENT_KEY_EXCHANGE && result == 1){
			psk_identity_length = (input[offset]<<8)+input[offset+1];
			memcpy(psk_identity, input+offset+2, psk_identity_length);
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
			if(!decrypt(finished_clear, client_write_key, nonce, input+offset+8, msg_length-8, additional_data)){
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
			sha256_update(&ctx, (unsigned char*)finished_clear, 16);
		}
		response_to_client_messages(result);
		if (result!=1) return 0;
	} else {
		uint8_t result = process_server_messages(input,
				msg_length, offset, expected_message);

		if(expected_message == SERVER_HELLO && result == 1){
			//save server_random
			memcpy(server_random, input+offset+2, 32);
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

			if(mmem_alloc(&mmem, msg_length - 16)==0){
				error(2, 80);
				return 0;
			}
			finished_clear = (char*)MMEM_PTR(&mmem);

			if(!decrypt(finished_clear, server_write_key, nonce, input+offset+8, msg_length-8, additional_data)){

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

/***************************************************************/
/*                      Handler functions                      */
/***************************************************************/
static int process_record(char* record, int record_length){
	uint8_t i,j;
	if (alert_received){
		alert_received = 0;
		if (record[1] == 0){
			error(1,0);
			return 0;
		} else {
			if (server) num_connected--;
			state = READY;
			record_state = RECORD_READY;
			recv_length = 0;
			message_recv_length = 0;
			sha256_init(&ctx);
			send_error = 1;
			return 0;
		}
	}
	if (!server && handshake_done && record[0]==((char)hello_request & 0xFF) && record_length == 12){
		rehandshake();
		return 1;
	}
	if (expected_message == APPLICATION_DATA || expected_message == FINISHED){
		if(act_on_full_message(record, record_length, 0)!=1) return 0;
		return 1;
	}
	if (expected_message != CHANGE_CIPHER_SPEC) sha256_update(&ctx, (unsigned char*)record, record_length);
	switch (record_state){
	case RECORD_RECV_MSG: //we are in this state when the message is arbitrary fragmented
			if (message_recv_length + record_length >= message_length) { //we have all we need plus maybe more
				j = message_recv_length;
				for (i = 0; j < message_length; i++) {
					record_buffer[j++] = record[i];
				}
				if (act_on_full_message(record_buffer, message_length, 0)!=1) return 0;

				mmem_free(&record_mmem);
				state = READY;
				if (record_length>i) process_record(record+i, record_length-i);
			} else {
				j = message_recv_length;
				for (i = 0; i < record_length; i++) {
					record_buffer[j++] = record[i];
				}
				message_recv_length = j; //still didn't get the whole message
				return 1;

			}
			break;
	case RECORD_RECV_HEADER:
		if ((record_length + message_recv_length) < 4){  //this is super unlikely
			for (i = 0; i < record_length; i++) {
				record_buffer[message_recv_length + i] = record[i];
			}
			message_recv_length += record_length;
			return 1;
		}else {
			for (i = 0; message_recv_length < 4; i++) {
				record_buffer[message_recv_length + i] = record[i];
				message_recv_length++;
			}
			j = i;

			memset(&message_length, (unsigned char)record[3],1);
			memset(&message_length+1, (unsigned char)record[2],1);
			memset(&message_length+2,(unsigned char)record[1],1);
			//message_length = ((unsigned char)record[1] << 16) + ((unsigned char)record[2] << 8) + (unsigned char)record[3];
			mmem_free(&record_mmem);
			if (record_length - i < message_length) { //message fragmented

				if (mmem_alloc(&record_mmem, message_length) == 0){
					error(2, 80);
					return 0;
				}
				record_buffer = (char*)MMEM_PTR(&record_mmem);
				for (; i < record_length; i++) {
					record_buffer[i - j] = record[i]; //copy the message to the buffer
				}
				message_recv_length = i - j;
				state = RECV_MSG;
				return 1;
			} else {
				//ok i have the whole message (or more), pass it to a function that will parse it
				//also give an offset j
				if (act_on_full_message(record, message_length, j)!=1) return 0;
				if (record_length - j > message_length) {
					record_state=RECORD_READY;
					process_record(record+j+message_length, record_length-j-message_length);
				}
			}
		}
		break;
	case RECORD_READY:
		if ((expected_message == CLIENT_HELLO && (record[0]!=((char)client_hello & 0xFF))) ||
				(expected_message == CLIENT_KEY_EXCHANGE && (record[0]!=((char)client_key_exchange & 0xFF))) ||
				(expected_message == SERVER_HELLO && (record[0]!=((char)server_hello & 0xFF))) ||
				(expected_message == SERVER_HELLO_DONE && (record[0]!=((char)server_hello_done & 0xFF)))){
			error(2, 10);
			return 0;
		}
		if (expected_message == CHANGE_CIPHER_SPEC){
			if (act_on_full_message(record, 1, 0)!=1) return 0;

			if (record_length > 1) {
				//we have more to process, pass it back to the function
				process_record(record+1, record_length-1);
			}
			return 1;
		}
		if(record_length < 4){
			//message was fragmented by the record protocol, need to get the next record
			//save what we got to the record_buffer
			record_state = RECORD_RECV_HEADER;

			if(mmem_alloc(&record_mmem, 4)==0){
				error(2, 80);
				return 0;
			}
			record_buffer = (char*)MMEM_PTR(&record_mmem);
			for (i = 0; i < record_length; i++) {
				record_buffer[i] = record[i];
			}
			message_recv_length = record_length;
			return 1;
		}

		memset(&message_length, (unsigned char)record[3],1);
		memset(&message_length+1, (unsigned char)record[2],1);
		memset(&message_length+2,(unsigned char)record[1],1);
		//message_length = ((unsigned char)record[1] << 16) + ((unsigned char)record[2] << 8) + (unsigned char)record[3];
		if (record_length < 4 + message_length) {
			//received fragment doesn't contain the complete sent message

			if(mmem_alloc(&record_mmem, message_length)==0){
				error(2, 80);
				return 0;
			}
			record_buffer = (char*)MMEM_PTR(&record_mmem);
			for (i = 4; i < record_length; i++) {
				record_buffer[i - 4] = record[i];
			}
			message_recv_length = record_length - 4;
			record_state = RECORD_RECV_MSG;
			return 1;
		} else {
			//
			if (act_on_full_message(record, message_length, 4)!=1) return 0;

			if (record_length > 4 + message_length) {
				//we have more to process, pass it back to the function
				process_record(record+message_length+4, record_length-message_length-4);
			}
		}
		break;
	}
	return 1;
}
static void process_input(char* input, int input_length){
	uint8_t i, j;
	switch (state) {
	case RECV_MSG: //we are in this state when the message is arbitrary fragmented
		if (recv_length + input_length >= record_length) { //we have all we need plus maybe more
			j = recv_length;
			for (i = 0; j < record_length; i++) {
				buffer[j++] = input[i];
			}
		//	if (act_on_full_message(buffer, record_length, 0)!=1) return;
			if (process_record(buffer, record_length)!=1) return;
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
			record_length = ((unsigned char)buffer[3] << 8) + ((unsigned char)buffer[4]);

			mmem_free(&process_mmem);
			if (input_length - i < record_length) { //message fragmented

				if (mmem_alloc(&process_mmem, record_length) == 0){
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
				if (process_record(input+j, record_length)!=1) return;
				//if (act_on_full_message(input, record_length, j)!=1) return;
				if (input_length - j > record_length) {
					state=READY;
					process_input(input+j+record_length, input_length-j-record_length);
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
				if (server && input[0]==0x16){
					expected_message = CLIENT_HELLO;
					sha256_init(&ctx);
					mmem_free(&datammem);
					if (!first_data_sent) mmem_free(&mmem);
					first_data_sent = 1;
					first_data = 1;
					handshake_done = 0;
				} else {
					error(2, 10);
					return;
				}
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

		record_length = ((unsigned char)input[3] << 8) + ((unsigned char)input[4]);
		if (input_length < 5 + record_length) {
			//received message doesn't contain the complete sent record (was fragmented)

			if(mmem_alloc(&process_mmem, record_length)==0){
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
			if (process_record(input+5, record_length)!=1) return;

			if (input_length > 5 + record_length) {
				//we have more to process, pass it back to the function
				process_input(input+record_length+5, input_length-record_length-5);
			}
		}
		break;
	}
}


static void handshake_event_handler(process_event_t ev, process_data_t data) {

	if (ev == tcpip_event) {
		if (server)process_post(calling_process, ev, data);
		if (wait_for_ack){
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

			if (server) {

				client_conn = uip_conn;
				if (num_connected == MAX_CONNECTIONS) {
					//send an internal_error alert (fatal)
					uip_send(internal_error, 7);

					mmem_free(&process_mmem);
					uip_close();
					return;
				}
				num_connected++;
				state = READY;
			} else {
				tcp_send(buffer, 50);

				mmem_free(&process_mmem);

			}
		} else if (uip_newdata()) {
			process_input((char*)uip_appdata, uip_datalen());
		} else if (uip_closed()){
			if (server) {
				num_connected--;
				expected_message = CLIENT_HELLO;
			} else {
				expected_message = SERVER_HELLO;
			}
			state = READY;
			record_state = RECORD_READY;
			recv_length = 0;
			message_recv_length = 0;

			if(!first_data)mmem_free(&datammem);
			first_data = 1;
			mmem_free(&sec_mmem);
			mmem_free(&conn_mmem);
			send_error = 1;
		}
	}
}
/***************************************************************/
/*                         Processes                           */
/***************************************************************/
PROCESS_THREAD(tls_client_handshake_process, ev, data) {
PROCESS_BEGIN();
	cur_process = PROCESS_CURRENT();
	Data* d = (struct Data*) data;
	uip_ipaddr_t* addr = d->addr;
	uint16_t port = d->port;
	client_conn = tcp_connect(addr, UIP_HTONS(port), NULL);
	sha256_init(&ctx);
	/*Create Client Hello message*/

	if (mmem_alloc(&process_mmem,50)==1){
		buffer = (char*)MMEM_PTR(&process_mmem);
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
				break;
			}
			handshake_event_handler(ev, data);
		}
	}
PROCESS_END();
}

PROCESS_THREAD(tls_server_listen, ev, data) {
	PROCESS_BEGIN();
	cur_process = PROCESS_CURRENT();
	uint16_t port = *(uint16_t*) data;
	tcp_listen(UIP_HTONS(port));
	sha256_init(&ctx); //initialize the context for the hashing function
	while (1) {
		PROCESS_YIELD();
		handshake_event_handler(ev, data);
		if (send_error){
			send_error = 0;
			uip_close();

		}

	}
	PROCESS_END();
}
