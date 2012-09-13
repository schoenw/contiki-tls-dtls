#include <contiki.h>
#include <contiki-net.h>
#include <contiki-lib.h>
#if TLS
#include <net/tls/tls.h>
#endif
#include <avr/io.h>
#include "raven-lcd.h"
#include <string.h>
#define CLOSE_INTERVAL 5 * CLOCK_CONF_SECOND

PROCESS(tls_client_test_process, "TLS");
AUTOSTART_PROCESSES(&tls_client_test_process);
#define TLS 1
#if TLS
static Connection* connection;
#else
static struct uip_conn *client_conn;
#endif


static struct etimer et;
static int exp_hello = 0;
static int exp_get1 = 0;
static int exp_get2 = 0;
static int exp_end = 0;
static int exp_set = 0;
static char result[10];
static char* find_name(char* input, int length){
	int i = 0;
	while(1){
		while (input[i]!='<' && i < length) i++;
		if(i==length) return "";
		i++;

			if(input[i]!='n') continue;
			else break;
	}
	i+=5;
	int j = i;
	while(input[i]!='<' && i < length){
		result[i-j] = input[i];
		i++;
	}
	return result;
}
#if TLS
static void tls_handler(process_event_t ev, process_data_t data){
	char* hello_msg = "<?xml version='1.0' encoding='UTF-8'?><hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><capabilities><capability>urn:ietf:params:netconf:base:1.1</capability></capabilities></hello>]]>]]>";
	if (ev == tls_event){
		if (tls_connected()){
			exp_hello=1;
			connection = (Connection*)data;
		} else if (tls_newdata()){
			if(exp_hello){
				TLS_Write(connection, hello_msg, strlen(hello_msg));
				etimer_set(&et, CLOCK_CONF_SECOND*10);

			} else if (exp_get1 || exp_set){
				char* name = find_name(tls_appdata, tls_applen);

				if(strcmp(name,"")){
					raven_lcd_show_text(name);
				}
			} else if (exp_set){
			} else{
				//TLS_Write(connection, hello_msg, strlen(hello_msg));
			//	etimer_set(&et, CLOCK_CONF_SECOND*5);
			}
		}
	} else if (ev == PROCESS_EVENT_TIMER){
		char* get_msg = "\n#175\n<?xml version='1.0' encoding='UTF-8'?><rpc message-id=\"101\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><get-config><source><running></running></source></get-config></rpc>\n##\n";
		char* set_msg = "\n#244\n<?xml version='1.0' encoding='UTF-8'?><rpc message-id=\"101\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><copy-config><target><running /></target><source><config><lcd>hello world2</lcd><name>Steve</name></config></source></copy-config></rpc>\n##\n";
		if (etimer_expired(&et) && exp_hello){

			TLS_Write(connection, get_msg, strlen(get_msg));
			exp_hello = 0;
			exp_get1 = 1;
			etimer_restart(&et);
		} else if (etimer_expired(&et) && exp_get1){

			TLS_Write(connection, set_msg, strlen(set_msg));
			exp_get1 = 0;
			exp_get2 = 1;
			etimer_restart(&et);
		}  else if (etimer_expired(&et) && exp_get2){

			TLS_Write(connection, get_msg, strlen(get_msg));
			exp_get2 = 0;
			exp_set = 1;
			etimer_restart(&et);
		} else if (etimer_expired(&et) && exp_set){

			char* end_msg = "\n#94\n<rpc message-id=\"102\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n<close-session/>\n</rpc>\n##\n";
			TLS_Write(connection, end_msg, strlen(end_msg));
			exp_set = 0;
			exp_end = 1;
		}

	}
}
#else
static void tcp_handler(process_event_t ev, process_data_t data){
	char* hello_msg = "<?xml version='1.0' encoding='UTF-8'?><hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><capabilities><capability>urn:ietf:params:netconf:base:1.1</capability></capabilities></hello>]]>]]>";
	if (ev == tcpip_event){
		if (uip_connected()){
			etimer_set(&et, CLOCK_CONF_SECOND*10);
		} else if (uip_newdata()){

			((char*)uip_appdata)[uip_datalen()]= 0;

			if(exp_hello){


			} else if (exp_get){
				char* name = find_name((char*)uip_appdata, uip_datalen());
				raven_lcd_show_text(name);
				if(strcmp(name,"")){
					exp_get = 0;
					exp_end = 1;
				}
			} else if (exp_end){
			} else{
				uip_send(hello_msg, strlen(hello_msg));
			}
		}
	} else if (ev == PROCESS_EVENT_TIMER){
		if (etimer_expired(&et)){
			char* get_msg = "\n#175\n<?xml version='1.0' encoding='UTF-8'?><rpc message-id=\"101\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><get-config><source><running></running></source></get-config></rpc>\n##\n";
			uip_send(get_msg, strlen(get_msg));
			tcpip_poll_tcp(client_conn);
			exp_hello = 0;
			exp_get = 1;
		}
	}
}
#endif


static void set_connection_address(uip_ipaddr_t *ipaddr)
{
	// uip_ip6addr(ipaddr, 0x2001,0x0638,0x0709,0x0010,0x021b,0x77ff,0xfeb5,0xd743);
	uip_ip6addr(ipaddr, 0x2001,0x0638,0x0709,0x000a,0x0011,0x22ff,0xfe17,0xa564);

}

PROCESS_THREAD(tls_client_test_process, ev, data)
{
  PROCESS_BEGIN();
	uip_ipaddr_t ipaddr;
	set_connection_address(&ipaddr);
#if TLS
	TLS_Connect(&ipaddr, 443);
#else
	client_conn = tcp_connect(&ipaddr, UIP_HTONS(3000), NULL);

#endif
	while(1){
		PROCESS_YIELD();
#if TLS
		tls_handler(ev, data);
#else
		tcp_handler(ev, data);
#endif
	}
  PROCESS_END();
}

