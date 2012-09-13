#include <contiki.h>
#include <contiki-net.h>
#include <contiki-lib.h>
#include <net/tls/tls.h>
#include <avr/io.h>
#include "raven-lcd.h"
#include <string.h>
#include "lib/mmem.h"
#define CLOSE_INTERVAL 2 * CLOCK_CONF_SECOND

PROCESS(tls_client_test_process, "1");
AUTOSTART_PROCESSES(&tls_client_test_process);
static Connection* connection;
static struct etimer et;
static char* hello_msg = "<?xml version='1.0' encoding='UTF-8'?><hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><capab";

static void tls_handler(process_event_t ev, process_data_t data){
	if (ev == tls_event){
		if (tls_connected()){
			connection = (Connection*)data;
			etimer_set(&et, CLOSE_INTERVAL);
			TLS_Write(connection, hello_msg, strlen(hello_msg));
		} else if (tls_newdata()){
			tls_appdata[tls_applen] = 0;
		}
	} else if (ev == PROCESS_EVENT_TIMER){
		if (etimer_expired(&et)){
			TLS_Write(connection, hello_msg, strlen(hello_msg));
			etimer_restart(&et);
		}
	}


}
static void set_connection_address(uip_ipaddr_t *ipaddr)
{
	uip_ip6addr(ipaddr, 0x2001,0x0638,0x0709,0x000a,0x0011,0x22ff,0xfe17,0xa4c6);
}

PROCESS_THREAD(tls_client_test_process, ev, data)
{
  PROCESS_BEGIN();
  //	mmem_init();
  etimer_set(&et, CLOCK_CONF_SECOND*5);
  	PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);
	uip_ipaddr_t ipaddr;
	set_connection_address(&ipaddr);
	TLS_Connect(&ipaddr, 443);
	while(1){
		PROCESS_YIELD();
		tls_handler(ev, data);
	}
  PROCESS_END();
}
