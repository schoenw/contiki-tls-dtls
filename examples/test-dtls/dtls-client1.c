#include <contiki.h>
#include <contiki-net.h>
#include <contiki-lib.h>
#include <net/dtls/dtls.h>
#include <avr/io.h>
#include "raven-lcd.h"
#include <string.h>
#include "lib/mmem.h"
#define SEND_INTERVAL 1 * CLOCK_CONF_SECOND
#define CLOSE_INTERVAL 120 * CLOCK_CONF_SECOND

PROCESS(dtls_client_test_process, "1");
AUTOSTART_PROCESSES(&dtls_client_test_process);
static Connection* connection;
static struct etimer et;
static struct etimer et2;
static char* hello_msg = "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
static uip_ipaddr_t ipaddr;
static void dtls_handler(process_event_t ev, process_data_t data){
	if (ev == dtls_event){
		if (dtls_rehandshake()){
			etimer_stop(&et);
		} else
		if (dtls_connected()){
			//raven_lcd_show_text("conn");
			connection = (Connection*)data;
			etimer_set(&et, SEND_INTERVAL);
			DTLS_Write(connection, hello_msg, 100);
		} else if (dtls_newdata()){
			dtls_appdata[5] = 0;
			
			raven_lcd_show_text(dtls_appdata);
			etimer_set(&et, CLOSE_INTERVAL);
			//DTLS_Write(connection, hello_msg, strlen(hello_msg));
		}
	} else if (ev == PROCESS_EVENT_TIMER){
		if (etimer_expired(&et)){
			DTLS_Write(connection, hello_msg, 100);
			etimer_reset(&et);
		}
		if (etimer_expired(&et2)){
			DTLS_Close(connection);
			etimer_stop(&et);
			etimer_stop(&et2);
		}
	}


}
static void set_connection_address(uip_ipaddr_t *ipaddr)
{
	// uip_ip6addr(ipaddr, 0x2001,0x0638,0x0709,0x0010,0x021b,0x77ff,0xfeb5,0xd743);
	// uip_ip6addr(ipaddr, 0x2001,0x0638,0x0709,0x000a,0x0011,0x22ff,0xfe17,0xa564); //laptop - usb0
	 uip_ip6addr(ipaddr, 0x2001,0x0638,0x0709,0x000a,0x0011,0x22ff,0xfe17,0xa4c6); //lisa - usb0

	// uip_ip6addr(ipaddr,  0x2001,0x0638,0x0709,0x0005,0x021c,0x23ff,0xfe91,0x9278);
}

PROCESS_THREAD(dtls_client_test_process, ev, data)
{
  PROCESS_BEGIN();
	
	set_connection_address(&ipaddr);
	etimer_set(&et, CLOCK_CONF_SECOND*10);
  	PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);
  	etimer_set(&et2, CLOSE_INTERVAL);
  	//raven_lcd_show_text("start");
	DTLS_Connect(&ipaddr, 4433);
	while(1){
		PROCESS_YIELD();
		dtls_handler(ev, data);
	}
  PROCESS_END();
}
