#include <contiki.h>
#include <contiki-net.h>
#include <contiki-lib.h>
#include <net/dtls/dtls.h>
//#include <avr/io.h>
//#include "raven-lcd.h"
#include <string.h>
#include "lib/mmem.h"
#if CONTIKI_TARGET_MINIMAL_NET
#ifndef DEBUG
#define DEBUG DEBUG_PRINT
#endif
#include "net/uip-debug.h"
#endif
PROCESS(dtls_client_test_process, "DTLS client test process");
AUTOSTART_PROCESSES(&dtls_client_test_process);
static Connection* connection;
static struct etimer et;
static struct etimer et2;
#define SEND_INTERVAL 1 * CLOCK_CONF_SECOND
static char* hello_msg = "hellooo";
static uip_ipaddr_t ipaddr;
static void dtls_handler(process_event_t ev, process_data_t data){
if (ev == dtls_event){
		if (dtls_rehandshake()){
			etimer_stop(&et);
		} else
		if (dtls_connected()){
			//raven_lcd_show_text("conn");
			PRINTF("CONNECTED\n");
			connection = (Connection*)data;
			etimer_set(&et, SEND_INTERVAL);
			DTLS_Write(connection, hello_msg, strlen(hello_msg));
		} else if (dtls_newdata()){
			dtls_appdata[dtls_applen] = 0;
			PRINTF("GOT NEW DATA: %s\n", dtls_appdata);
			//raven_lcd_show_text(dtls_appdata);
		}
	} else if (ev == PROCESS_EVENT_TIMER){
		if (etimer_expired(&et)){
			DTLS_Write(connection, hello_msg, strlen(hello_msg));
			etimer_reset(&et);
		}
	}

}

static void set_connection_address(uip_ipaddr_t *ipaddr)
{
	// uip_ip6addr(ipaddr, 0x2001,0x0638,0x0709,0x000a,0x0011,0x22ff,0xfe17,0xa4c6); //lisa - usb0
	uip_ip6addr(ipaddr, 0xfe80,0x0000,0x0000,0x0000,0x0000,0x00ff,0xfe02,0x0232);
}

PROCESS_THREAD(dtls_client_test_process, ev, data)
{
  PROCESS_BEGIN();
	set_connection_address(&ipaddr);
	etimer_set(&et, CLOCK_CONF_SECOND*10);
  	PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);
  	
  	//raven_lcd_show_text("start");
	DTLS_Connect(&ipaddr, 20220);
	while(1){
		PROCESS_YIELD();
		PRINTF("Client awaken!\n");
		dtls_handler(ev, data);
	}
  PROCESS_END();
}
